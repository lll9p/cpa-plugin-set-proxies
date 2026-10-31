package plugin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const pluginVersion = "1.0.0"

const base = "/v0/management/plugins/cpa-plugin-set-proxies"
const resource = "/v0/resource/plugins/cpa-plugin-set-proxies/ui"
const planTTL = 10 * time.Minute
const maxSettingsSize = 64 << 10

type config struct {
	URL      string   `json:"webshare_url"`
	Key      string   `json:"management_key"`
	Excludes []string `json:"excludes"`
}
type row struct {
	Name     string `json:"name"`
	Index    string `json:"auth_index"`
	Current  string `json:"current_endpoint"`
	Proposed string `json:"proposed_endpoint"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}
type summary struct {
	Proxies     int `json:"proxies"`
	Alive       int `json:"alive"`
	Credentials int `json:"credentials"`
	Kept        int `json:"kept"`
	Pending     int `json:"pending"`
	External    int `json:"external"`
	Excluded    int `json:"excluded"`
}
type state struct {
	Configured bool          `json:"configured"`
	KeySet     bool          `json:"management_key_set"`
	Excludes   []string      `json:"excludes"`
	Phase      string        `json:"phase"`
	Stage      string        `json:"stage"`
	Done       int           `json:"done"`
	Total      int           `json:"total"`
	Summary    summary       `json:"summary"`
	Rows       []row         `json:"rows"`
	PlanID     string        `json:"plan_id"`
	Error      string        `json:"error"`
	Results    []applyResult `json:"results"`
}
type assignment struct {
	Name, Index, Path, Expected, Proxy string
}
type backend struct {
	mu           sync.Mutex
	life         sync.Mutex
	quiesced     bool
	cfg          config
	settingsPath string
	host         func(string, any) (json.RawMessage, error)
	s            state
	cancel       context.CancelFunc
	finished     chan struct{}
	assignments  []assignment
	expires      time.Time
	fetch        func(context.Context, string) ([]node, error)
	probe        func(context.Context, node) bool
	endpoint     func() (string, error)
	client       *http.Client
}

var service = &backend{
	s:            state{Phase: "idle", Rows: []row{}, Excludes: []string{}, Results: []applyResult{}},
	settingsPath: filepath.Join("data", "cpa-plugin-set-proxies", "settings.json"),
	fetch:        fetchNodes, probe: probeNode, endpoint: cpaEndpoint, client: managementClient(),
}

func SetHostCall(f func(string, any) (json.RawMessage, error)) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.host = f
}
func Quiesce() { service.life.Lock(); defer service.life.Unlock(); service.stop() }
func (b *backend) stop() {
	b.mu.Lock()
	b.quiesced = true
	c, ch := b.cancel, b.finished
	if c != nil {
		c()
	}
	b.assignments = nil
	b.s.PlanID = ""
	b.mu.Unlock()
	if ch != nil {
		<-ch
	}
	b.client.CloseIdleConnections()
}
func (b *backend) initialState() state {
	return state{Phase: "idle", Configured: b.cfg.URL != "", KeySet: b.cfg.Key != "", Excludes: b.cfg.Excludes, Rows: []row{}, Results: []applyResult{}}
}
func envelope(v any) ([]byte, error) { return json.Marshal(map[string]any{"ok": true, "result": v}) }
func invalid() ([]byte, error) {
	return json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": "invalid_request", "message": "Invalid plugin request"}})
}
func HandleMethod(method string, raw []byte) ([]byte, error) { return service.handle(method, raw) }
func (b *backend) handle(method string, raw []byte) ([]byte, error) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		var p struct {
			Config []byte `json:"config_yaml"`
		}
		if !jsonObject(raw) || json.Unmarshal(raw, &p) != nil {
			return invalid()
		}
		b.life.Lock()
		defer b.life.Unlock()
		b.stop()
		c, err := loadSettings(b.settingsPath)
		if err != nil {
			return json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": "settings_error", "message": "Unable to load plugin settings"}})
		}
		b.mu.Lock()
		b.cfg = c
		b.quiesced = false
		b.s = b.initialState()
		b.mu.Unlock()
		return envelope(map[string]any{"schema_version": 6, "metadata": map[string]any{"Name": "cpa-plugin-set-proxies", "Version": pluginVersion, "Author": "lll9p", "GitHubRepository": "https://github.com/lll9p/cpa-plugin-set-proxies", "ConfigFields": []any{}}, "capabilities": map[string]bool{"management_api": true}})
	case "plugin.quiesce", "plugin.shutdown":
		b.life.Lock()
		defer b.life.Unlock()
		b.stop()
		return envelope(map[string]any{})
	case "management.register":
		return envelope(map[string]any{
			"routes": []any{
				map[string]string{"Method": "GET", "Path": base + "/state"},
				map[string]string{"Method": "POST", "Path": base + "/settings"},
				map[string]string{"Method": "POST", "Path": base + "/scan"},
				map[string]string{"Method": "POST", "Path": base + "/cancel"},
				map[string]string{"Method": "POST", "Path": base + "/apply"},
			},
			"resources": []any{map[string]string{"Path": resource, "Menu": "代理分配", "Description": "Scan proxies and preview credential assignments"}},
		})
	case "management.handle":
		var req struct {
			Method, Path string
			Headers      http.Header
			Body         []byte
		}
		if !jsonObject(raw) || json.Unmarshal(raw, &req) != nil {
			return response(400, map[string]string{"error": "Invalid JSON"})
		}
		if req.Path == resource {
			if req.Method != "GET" {
				return response(405, nil)
			}
			headers := responseHeaders("text/html; charset=utf-8")
			headers.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
			return envelope(map[string]any{"StatusCode": 200, "Headers": headers, "Body": uiHTML()})
		}
		switch req.Path {
		case base + "/state":
			if req.Method != "GET" {
				return response(405, nil)
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			return response(200, b.s)
		case base + "/settings", base + "/scan", base + "/cancel", base + "/apply":
			if req.Method != "POST" {
				return response(405, nil)
			}
			if len(req.Body) > maxSettingsSize || !jsonObject(req.Body) || !json.Valid(req.Body) {
				return response(400, map[string]string{"error": "Invalid JSON"})
			}
			switch req.Path {
			case base + "/settings":
				return b.saveSettings(req.Body)
			case base + "/scan":
				return b.start()
			case base + "/cancel":
				return b.cancelTask()
			case base + "/apply":
				var p struct {
					ID string `json:"plan_id"`
				}
				if json.Unmarshal(req.Body, &p) != nil {
					return response(400, map[string]string{"error": "Invalid JSON"})
				}
				return b.apply(p.ID)
			}
		}
		return response(404, nil)
	}
	return invalid()
}
func response(code int, v any) ([]byte, error) {
	body, _ := json.Marshal(v)
	return envelope(map[string]any{"StatusCode": code, "Headers": responseHeaders("application/json"), "Body": body})
}
func validURL(s string) bool {
	if s == "" {
		return true
	}
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil && !strings.ContainsAny(s, "\r\n")
}
func id() (string, error) {
	var p [16]byte
	if _, err := io.ReadFull(rand.Reader, p[:]); err != nil {
		return "", errors.New("Unable to generate identifier")
	}
	return hex.EncodeToString(p[:]), nil
}
func (b *backend) saveSettings(raw []byte) ([]byte, error) {
	var p struct {
		URL      string          `json:"webshare_url"`
		Key      json.RawMessage `json:"management_key"`
		Excludes *[]string       `json:"excludes"`
		ClearURL bool            `json:"clear_webshare_url"`
	}
	if len(raw) > maxSettingsSize || !jsonObject(raw) || json.Unmarshal(raw, &p) != nil {
		return response(400, map[string]string{"error": "Invalid JSON"})
	}
	var key string
	if p.Key != nil && (string(p.Key) == "null" || json.Unmarshal(p.Key, &key) != nil) {
		return response(400, map[string]string{"error": "Invalid settings or missing management key"})
	}
	p.URL = strings.TrimSpace(p.URL)
	if strings.ContainsAny(key, "\r\n") || !validURL(p.URL) || p.ClearURL && p.URL != "" {
		return response(400, map[string]string{"error": "Invalid settings or missing management key"})
	}
	b.life.Lock()
	defer b.life.Unlock()
	b.mu.Lock()
	if b.quiesced {
		b.mu.Unlock()
		return response(503, map[string]string{"error": "Plugin is quiesced"})
	}
	if b.cancel != nil {
		b.mu.Unlock()
		return response(409, map[string]string{"error": "Task already running"})
	}
	c := b.cfg
	b.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" && c.Key == "" {
		return response(400, map[string]string{"error": "Invalid settings or missing management key"})
	}
	if key != "" {
		endpoint, err := b.endpoint()
		if err != nil {
			return response(500, map[string]string{"error": "Unable to read CPA listener configuration"})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v0/management/plugins", nil)
		if err != nil {
			return response(502, map[string]string{"error": "Unable to verify CPA management password"})
		}
		req.Header.Set("Authorization", "Bearer "+key)
		res, err := b.client.Do(req)
		if err != nil {
			return response(502, map[string]string{"error": "Unable to verify CPA management password"})
		}
		res.Body.Close()
		if res.StatusCode == 401 || res.StatusCode == 403 {
			return response(422, map[string]string{"error": "CPA management authentication failed"})
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return response(502, map[string]string{"error": "Unable to verify CPA management password"})
		}
		c.Key = key
	}
	if p.ClearURL || p.URL != "" {
		c.URL = p.URL
	}
	if p.Excludes != nil {
		c.Excludes = []string{}
		for _, name := range *p.Excludes {
			if name = strings.TrimSpace(name); name != "" {
				c.Excludes = append(c.Excludes, name)
			}
		}
	}
	if err := writeSettings(b.settingsPath, c); err != nil {
		return response(500, map[string]string{"error": "Unable to save plugin settings"})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = c
	b.assignments = nil
	b.s = b.initialState()
	return response(200, b.s)
}
func (b *backend) start() ([]byte, error) {
	b.life.Lock()
	defer b.life.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.quiesced {
		return response(503, map[string]string{"error": "Plugin is quiesced"})
	}
	if b.cancel != nil {
		return response(409, map[string]string{"error": "Task already running"})
	}
	c := b.cfg
	if c.URL == "" || !validURL(c.URL) {
		return response(400, map[string]string{"error": "Invalid or missing Webshare configuration"})
	}
	scanID, err := id()
	if err != nil {
		return response(500, map[string]string{"error": "Unable to start scan"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.finished = make(chan struct{})
	b.assignments = nil
	b.s = b.initialState()
	b.s.Phase, b.s.Stage = "scanning", "fetch"
	go b.run(ctx, c, b.finished)
	return response(202, map[string]string{"scan_id": scanID})
}
func (b *backend) cancelTask() ([]byte, error) {
	b.life.Lock()
	defer b.life.Unlock()
	b.mu.Lock()
	ch := b.finished
	if b.cancel != nil {
		b.s.Phase = "cancelling"
		b.cancel()
	} else if b.s.Phase == "ready" {
		b.s.Phase = "cancelled"
	}
	b.assignments = nil
	b.s.PlanID = ""
	b.mu.Unlock()
	if ch != nil {
		<-ch
	}
	return response(200, map[string]bool{"cancelled": true})
}
func (b *backend) call(method string, p any) (json.RawMessage, error) {
	b.mu.Lock()
	h := b.host
	b.mu.Unlock()
	if h == nil {
		return nil, errors.New("Host unavailable")
	}
	r, e := h(method, p)
	if e != nil {
		return nil, errors.New("Credential read failed")
	}
	return r, nil
}
func responseHeaders(contentType string) http.Header {
	return http.Header{"Content-Type": {contentType}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"}}
}
func jsonObject(raw []byte) bool { return strings.HasPrefix(strings.TrimSpace(string(raw)), "{") }
