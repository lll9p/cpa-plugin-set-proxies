package plugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type node struct{ Host, Port, User, Password string }

func (n node) endpoint() string { return net.JoinHostPort(n.Host, n.Port) }
func (n node) URL() string {
	return (&url.URL{Scheme: "socks5", Host: n.endpoint(), User: url.UserPassword(n.User, n.Password), Path: "/"}).String()
}
func identity(s string) (node, bool) {
	u, e := url.Parse(s)
	if e != nil || u == nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") || u.Hostname() == "" {
		return node{}, false
	}
	p, e := strconv.Atoi(u.Port())
	if e != nil || p < 1 || p > 65535 {
		return node{}, false
	}
	n := node{Host: u.Hostname(), Port: strconv.Itoa(p)}
	if u.User != nil {
		n.User = u.User.Username()
		n.Password, _ = u.User.Password()
	}
	return n, true
}
func display(s string) string {
	if s == "" || s == "direct" || s == "none" {
		return s
	}
	u, e := url.Parse(s)
	if e != nil || u.Hostname() == "" {
		return ""
	}
	return u.Host
}

type downloadError string

func (e downloadError) Error() string { return string(e) }

func downloadFailure(err error) downloadError {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var network net.Error
	switch {
	case errors.As(err, &dns):
		return "Proxy download DNS failed"
	case errors.As(err, &cert):
		return "Proxy download TLS failed"
	case errors.As(err, &network) && network.Timeout():
		return "Proxy download timed out"
	default:
		return "Proxy download network failed"
	}
}

func fetchNodes(ctx context.Context, address string) ([]node, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, downloadError("Proxy download request invalid")
	}
	req.Header.Set("User-Agent", "cpa-plugin-set-proxies/1.0")
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		return nil, downloadFailure(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		if res.StatusCode == http.StatusNotFound {
			var detail struct {
				Detail string `json:"detail"`
			}
			if json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&detail) == nil &&
				strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(detail.Detail), "."), "Plan not found") {
				return nil, downloadError("Proxy download plan not found")
			}
		}
		return nil, downloadError("Proxy download HTTP " + strconv.Itoa(res.StatusCode))
	}
	const maxDownload = 16 << 20
	data, e := io.ReadAll(io.LimitReader(res.Body, maxDownload+1))
	if e != nil {
		return nil, downloadFailure(e)
	}
	if len(data) > maxDownload {
		return nil, downloadError("Proxy download exceeds size limit")
	}
	var out []node
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.SplitN(strings.TrimSpace(line), ":", 4)
		if len(p) != 4 {
			continue
		}
		port, e := strconv.Atoi(p[1])
		if e != nil || port < 1 || port > 65535 || p[0] == "" {
			continue
		}
		out = append(out, node{p[0], strconv.Itoa(port), p[2], p[3]})
	}
	if len(out) == 0 {
		if strings.TrimSpace(string(data)) == "" {
			return nil, downloadError("Proxy list empty")
		}
		return nil, downloadError("Proxy list format invalid")
	}
	return out, nil
}
func probeNode(ctx context.Context, n node) bool {
	return probeNodeDetailed(ctx, n).Alive
}

func probeCategory(ctx context.Context, err error, tlsStage bool) string {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return ""
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	if tlsStage {
		return "tls"
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if op, ok := cause.(*net.OpError); ok && op.Op == "dial" {
			return "connect"
		}
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "socks connect" {
		// x/net exposes no sentinel for SOCKS authentication or protocol failures.
		switch op.Err.Error() {
		case "username/password authentication failed", "invalid username/password", "no acceptable authentication methods":
			return "socks_auth"
		case "invalid username/password version", "non-zero reserved field",
			"unknown error general SOCKS server failure", "unknown error connection not allowed by ruleset",
			"unknown error network unreachable", "unknown error host unreachable", "unknown error connection refused",
			"unknown error TTL expired", "unknown error command not supported", "unknown error address type not supported":
			return "socks"
		}
	}
	return "unknown"
}

func probeNodeDetailed(ctx context.Context, n node) (result ProbeResult) {
	started := time.Now()
	defer func() { result.DurationMS = time.Since(started).Milliseconds() }()
	d, err := proxy.SOCKS5("tcp", n.endpoint(), &proxy.Auth{User: n.User, Password: n.Password}, &net.Dialer{})
	tlsStage := false
	if err == nil {
		var c net.Conn
		c, err = d.(proxy.ContextDialer).DialContext(ctx, "tcp", "www.cloudflare.com:443")
		if err == nil {
			defer c.Close()
			tlsStage = true
			t := tls.Client(c, &tls.Config{ServerName: "www.cloudflare.com", MinVersion: tls.VersionTLS12})
			err = t.HandshakeContext(ctx)
		}
	}
	if err == nil {
		result.Alive, result.Checked = true, true
	} else {
		result.Category = probeCategory(ctx, err, tlsStage)
		result.Checked = result.Category != ""
	}
	return result
}

type entry struct {
	Name    string `json:"name"`
	Index   string `json:"auth_index"`
	Path    string `json:"path"`
	Runtime bool   `json:"runtime_only"`
	Source  string `json:"source"`
}

func excludable(f entry) bool {
	return !f.Runtime && f.Source != "config" && f.Source != "memory" &&
		f.Name != "" && !strings.ContainsAny(f.Name, "/\\\x00") && strings.HasSuffix(strings.ToLower(f.Name), ".json") &&
		f.Path != "" && !strings.Contains(f.Path, "://") && !strings.ContainsRune(f.Path, '\x00') &&
		strings.HasSuffix(strings.ToLower(filepath.Base(f.Path)), ".json")
}

func (b *backend) read(index string) (string, string, error) {
	r, e := b.call("host.auth.get", map[string]string{"auth_index": index})
	if e != nil {
		return "", "", e
	}
	var doc struct {
		Path string                     `json:"path"`
		JSON map[string]json.RawMessage `json:"json"`
	}
	if json.Unmarshal(r, &doc) != nil || doc.JSON == nil {
		return "", "", errors.New("Invalid credential")
	}
	var v string
	if raw := doc.JSON["proxy_url"]; len(raw) > 0 && string(raw) != "null" {
		if json.Unmarshal(raw, &v) != nil {
			return "", "", errors.New("Invalid proxy setting")
		}
	}
	return strings.TrimSpace(v), doc.Path, nil
}
func (b *backend) run(ctx context.Context, c config, finished chan struct{}) {
	var failure string
	defer func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if ctx.Err() != nil {
			b.s.Phase = "cancelled"
			b.s.PlanID = ""
			b.assignments = nil
		} else if failure != "" {
			b.s.Phase = "failed"
			b.s.Error = failure
			b.s.PlanID = ""
			b.assignments = nil
		}
		b.cancel = nil
		close(finished)
	}()
	rows, stats, assignments, scanFailure := b.scanPlan(ctx, c)
	failure = scanFailure
	if failure != "" || ctx.Err() != nil {
		return
	}
	var planID string
	if len(assignments) > 0 {
		var err error
		planID, err = id()
		if err != nil {
			failure = "Unable to create plan"
			return
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	b.s.Rows = rows
	b.s.Summary = stats
	b.s.Phase = "ready"
	b.s.Stage = "complete"
	b.s.PlanID = planID
	b.expires = time.Now().Add(planTTL)
	b.assignments = assignments
}

func (b *backend) scanPlan(ctx context.Context, c config) (rows []row, stats summary, assignments []assignment, failure string) {
	nodes, e := b.fetch(ctx, c.URL)
	if e != nil {
		failure = "Proxy download network failed"
		var safe downloadError
		if errors.As(e, &safe) {
			failure = safe.Error()
		}
		return
	}
	if len(nodes) == 0 {
		failure = "Proxy list empty"
		return
	}
	b.mu.Lock()
	b.s.Stage = "probe"
	b.s.Total = len(nodes)
	b.s.Summary.Proxies = len(nodes)
	b.s.Probes = make([]ProbeResult, len(nodes))
	for i, n := range nodes {
		b.s.Probes[i].Endpoint = n.endpoint()
	}
	b.mu.Unlock()
	flags := make([]bool, len(nodes))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < min(24, len(nodes)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				for attempt := 1; attempt <= 3 && ctx.Err() == nil; attempt++ {
					pc, cancel := context.WithTimeout(ctx, 15*time.Second)
					var result ProbeResult
					if b.probe == nil {
						result = probeNodeDetailed(pc, nodes[i])
					} else {
						started := time.Now()
						result.Alive = b.probe(pc, nodes[i])
						result.DurationMS = time.Since(started).Milliseconds()
						result.Checked = result.Alive || !errors.Is(pc.Err(), context.Canceled)
						if result.Checked {
							result.Category = "unknown"
						}
					}
					cancel()
					if !result.Checked {
						break
					}
					if result.Alive || attempt == 3 {
						result.Endpoint, result.Attempts = nodes[i].endpoint(), attempt
						flags[i] = result.Alive
						b.mu.Lock()
						b.s.Probes[i] = result
						b.s.Done++
						b.mu.Unlock()
						break
					}
					select {
					case <-ctx.Done():
					case <-time.After(time.Second):
					}
				}
			}
		}()
	}
enqueue:
	for i := range nodes {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break enqueue
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	unique := map[string]node{}
	for i, n := range nodes {
		if flags[i] {
			unique[n.endpoint()] = n
		}
	}
	alive := make([]node, 0, len(unique))
	for _, n := range unique {
		alive = append(alive, n)
	}
	sort.Slice(alive, func(i, j int) bool {
		a, z := alive[i], alive[j]
		if a.Host != z.Host {
			return a.Host < z.Host
		}
		pi, _ := strconv.Atoi(a.Port)
		pj, _ := strconv.Atoi(z.Port)
		return pi < pj
	})
	if len(alive) == 0 {
		failure = "No live proxies"
		return
	}
	b.mu.Lock()
	b.s.Stage = "credentials"
	b.s.Summary.Alive = len(alive)
	b.mu.Unlock()
	raw, e := b.call("host.auth.list", map[string]any{})
	var listing struct {
		Files []entry `json:"files"`
	}
	if e != nil || json.Unmarshal(raw, &listing) != nil || listing.Files == nil {
		failure = "Credential listing failed"
		return
	}
	excludes := map[string]bool{}
	for _, s := range c.Excludes {
		excludes[strings.TrimSpace(s)] = true
	}
	// Block every alias of an excluded physical file before considering writes.
	blocked := map[string]bool{}
	for _, f := range listing.Files {
		if excludes[f.Name] && f.Path != "" {
			blocked[filepath.Clean(f.Path)] = true
		}
	}
	seenPath, seenName := map[string]bool{}, map[string]string{}
	used := map[string]bool{}
	var pending []int
	stats = summary{Proxies: len(nodes), Alive: len(alive)}
	for _, f := range listing.Files {
		if ctx.Err() != nil {
			return
		}
		r := row{Name: f.Name, Index: f.Index, Action: "skip", Excludable: excludable(f)}
		if excludes[f.Name] || f.Runtime || f.Source == "config" || f.Source == "memory" || blocked[filepath.Clean(f.Path)] {
			r.Reason = "excluded or runtime-only"
			stats.Excluded++
			rows = append(rows, r)
			continue
		}
		if f.Name == "" || f.Index == "" {
			failure = "Invalid credential listing"
			return
		}
		v, path, e := b.read(f.Index)
		if e != nil {
			failure = "Credential read failed"
			return
		}
		if f.Path != "" && (path == "" || filepath.Clean(path) != filepath.Clean(f.Path)) {
			failure = "Credential physical path changed"
			return
		}
		if path == "" {
			r.Reason = "no physical file"
			stats.Excluded++
			rows = append(rows, r)
			continue
		}
		path = filepath.Clean(path)
		f.Name = filepath.Base(path)
		r.Name = f.Name
		f.Path = path
		r.Excludable = excludable(f)
		if excludes[f.Name] || blocked[path] || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			r.Reason = "excluded or not a credential file"
			stats.Excluded++
			rows = append(rows, r)
			continue
		}
		if previous := seenName[f.Name]; previous != "" && previous != path {
			failure = "Ambiguous credential filename"
			return
		}
		if seenPath[path] {
			continue
		}
		seenPath[path] = true
		seenName[f.Name] = path
		stats.Credentials++
		r.Current = display(v)
		n, ok := identity(v)
		owned := false
		for _, p := range nodes {
			if ok && (p.endpoint() == n.endpoint() || (p.User != "" && p.Password != "" && p.User == n.User && p.Password == n.Password)) {
				owned = true
				break
			}
		}
		live := false
		for _, p := range alive {
			if p == n {
				live = true
				break
			}
		}
		if v == "" || (owned && !live) {
			r.Action = "assign"
			r.Reason = "needs live proxy"
			pending = append(pending, len(rows))
			assignments = append(assignments, assignment{Name: f.Name, Index: f.Index, Path: path, Expected: v})
			stats.Pending++
		} else if owned && live {
			r.Action = "keep"
			r.Proposed = r.Current
			r.Reason = "live identity"
			used[n.endpoint()] = true
			stats.Kept++
		} else {
			r.Reason = "external or explicit setting"
			stats.External++
		}
		rows = append(rows, r)
	}
	var unused []node
	for _, n := range alive {
		if !used[n.endpoint()] {
			unused = append(unused, n)
		}
	}
	for i, ri := range pending {
		var n node
		if i < len(unused) {
			n = unused[i]
		} else {
			n = alive[(i-len(unused))%len(alive)]
		}
		rows[ri].Proposed = n.endpoint()
		assignments[i].Proxy = n.URL()
	}
	return
}
