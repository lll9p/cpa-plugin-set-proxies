package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testBackend(t *testing.T, values []any) *backend {
	t.Helper()
	a := node{"10.0.0.1", "1080", "u", "p"}
	z := node{"10.0.0.2", "1080", "other", "p@ss:%word"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(server.Close)
	b := &backend{cfg: config{URL: "https://example.invalid", Key: "management-secret", Excludes: []string{}}, settingsPath: filepath.Join(t.TempDir(), "settings.json"), endpoint: func() (string, error) { return server.URL, nil }, client: managementClient(), fetch: func(context.Context, string) ([]node, error) { return []node{a, z}, nil }, probe: func(context.Context, node) bool { return true }}
	if err := writeSettings(b.settingsPath, b.cfg); err != nil {
		t.Fatal(err)
	}
	b.s = b.initialState()
	b.host = func(method string, p any) (json.RawMessage, error) {
		var v any
		switch method {
		case "host.auth.list":
			files := []entry{}
			for i := range values {
				files = append(files, entry{Name: string(rune('a'+i)) + ".json", Index: string(rune('a' + i)), Path: "/auth/" + string(rune('a'+i)) + ".json"})
			}
			v = map[string]any{"files": files}
		case "host.auth.get":
			index := p.(map[string]string)["auth_index"]
			value := values[int(index[0]-'a')]
			if value == "ERROR" {
				return nil, errors.New("sensitive secret")
			}
			v = map[string]any{"path": "/auth/" + index + ".json", "json": map[string]any{"proxy_url": value, "token": "refreshed"}}
		default:
			t.Fatalf("unexpected callback %s", method)
		}
		r, e := json.Marshal(v)
		return r, e
	}
	t.Cleanup(b.stop)
	return b
}
func scan(t *testing.T, b *backend) {
	t.Helper()
	raw, err := b.start()
	if err != nil || status(t, raw) != 202 {
		t.Fatalf("scan rejected: %s, %v", raw, err)
	}
	waitTask(t, b)
}
func waitTask(t *testing.T, b *backend) {
	t.Helper()
	b.mu.Lock()
	ch := b.finished
	b.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("task timeout")
	}
}
func status(t *testing.T, raw []byte) int {
	t.Helper()
	var e struct {
		Result struct {
			Status int `json:"StatusCode"`
		}
	}
	if json.Unmarshal(raw, &e) != nil {
		t.Fatal("invalid envelope")
	}
	return e.Result.Status
}
func TestAllocation(t *testing.T) {
	a := node{"10.0.0.1", "1080", "u", "p"}
	z := node{"10.0.0.2", "1080", "other", "p@ss:%word"}
	values := []any{strings.Replace(a.URL(), "socks5:", "socks5h:", 1), "", nil, " ", "", "", "", "", "direct", "none", "socks5://foreign:secret@10.0.0.9:1080", "socks5://[broken", "socks5://host:bad", "http://u:p@10.0.0.1:1080"}
	b := testBackend(t, values)
	scan(t, b)
	if b.s.Phase != "ready" || b.s.Summary.Kept != 1 || b.s.Summary.External != 6 {
		t.Fatalf("state %+v", b.s)
	}
	want := []node{z, a, z, a, z, a, z}
	for i, x := range b.assignments {
		if x.Proxy != want[i].URL() {
			t.Fatalf("assignment %d", i)
		}
	}
	raw, _ := json.Marshal(b.s)
	if strings.Contains(string(raw), "p@ss") || strings.Contains(string(raw), "foreign:secret") {
		t.Fatal("state leaks secret")
	}
}
func TestOwnership(t *testing.T) {
	for _, v := range []string{"socks5://old:old@10.0.0.1:1080", "socks5://other:p%40ss%3A%25word@10.0.0.9:1080"} {
		b := testBackend(t, []any{v})
		scan(t, b)
		if len(b.assignments) != 1 {
			t.Fatal("owned stale identity not replaced")
		}
	}
}
func TestInvalidReadsHaveNoPlan(t *testing.T) {
	for _, v := range []any{42, "ERROR"} {
		b := testBackend(t, []any{"", v})
		scan(t, b)
		if b.s.Phase != "failed" || b.s.PlanID != "" || len(b.assignments) != 0 {
			t.Fatal("failed scan has plan")
		}
	}
}
func TestApplyConflictAndExpiry(t *testing.T) {
	values := []any{"  "}
	b := testBackend(t, values)
	scan(t, b)
	values[0] = "direct"
	raw, _ := b.apply(b.s.PlanID)
	if status(t, raw) != 202 {
		t.Fatal("apply rejected")
	}
	waitTask(t, b)
	if len(b.s.Results) != 1 || b.s.Results[0].Status != "conflict" {
		t.Fatal("changed proxy accepted")
	}
	values[0] = nil
	scan(t, b)
	b.expires = time.Now().Add(-time.Second)
	raw, _ = b.apply(b.s.PlanID)
	if status(t, raw) != 409 {
		t.Fatal("expired accepted")
	}
}
func TestCancellationAndSingleTask(t *testing.T) {
	b := testBackend(t, []any{""})
	started := make(chan struct{})
	b.fetch = func(ctx context.Context, _ string) ([]node, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	b.start()
	<-started
	raw, _ := b.start()
	if status(t, raw) != 409 {
		t.Fatal("parallel scan accepted")
	}
	b.stop()
	if b.s.Phase != "cancelled" || b.s.PlanID != "" {
		t.Fatal("cancellation failed")
	}
}
func TestFetchOffline(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("10.0.0.1:1080:u:p:colon\ninvalid\nh:99999:u:p"))
	}))
	defer s.Close()
	n, e := fetchNodes(context.Background(), s.URL)
	if e != nil || len(n) != 1 || n[0].Password != "p:colon" {
		t.Fatal("parse failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = fetchNodes(ctx, s.URL); e == nil {
		t.Fatal("cancel ignored")
	}
}
func TestStaticResource(t *testing.T) {
	b := testBackend(t, nil)
	b.host = func(string, any) (json.RawMessage, error) { t.Fatal("public resource called host"); return nil, nil }
	request, _ := json.Marshal(map[string]any{"Method": "GET", "Path": resource})
	raw, e := b.handle("management.handle", request)
	if e != nil || status(t, raw) != 200 {
		t.Fatal("resource failed")
	}
	if strings.Contains(string(raw), "example.invalid") {
		t.Fatal("configuration leaked")
	}
}
func TestIdentity(t *testing.T) {
	n := node{"host", "1080", "u@ser:%", "p@ss:%word"}
	decoded, ok := identity(n.URL())
	if !ok || decoded != n {
		t.Fatal("percent decoding failed")
	}
	for _, s := range []string{"socks5://host:65536", "socks5://host", "socks5://[bad", "direct", "http://u:p@host:1080"} {
		if _, ok := identity(s); ok {
			t.Fatal(s)
		}
	}
}
func TestNoNodes(t *testing.T) {
	for _, mode := range []int{0, 1} {
		b := testBackend(t, []any{""})
		b.fetch = func(context.Context, string) ([]node, error) {
			if mode == 0 {
				return nil, nil
			}
			return nil, errors.New("secret URL")
		}
		scan(t, b)
		if b.s.Phase != "failed" || b.s.PlanID != "" {
			t.Fatal("bad download generated plan")
		}
	}
}
func TestPhysicalDedupAndExclusion(t *testing.T) {
	b := testBackend(t, []any{""})
	original := b.host
	b.host = func(m string, p any) (json.RawMessage, error) {
		if m == "host.auth.list" {
			return json.Marshal(map[string]any{"files": []entry{{Name: "a.json", Index: "a", Path: "/auth/a.json"}, {Name: "alias.json", Index: "a", Path: "/auth/a.json"}, {Name: "virtual", Runtime: true}}})
		}
		return original(m, p)
	}
	scan(t, b)
	if len(b.assignments) != 1 {
		t.Fatal("physical file duplicated")
	}
	b.cfg.Excludes = []string{"a.json"}
	scan(t, b)
	if len(b.assignments) != 0 {
		t.Fatal("excluded alias written")
	}
}
