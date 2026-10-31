package plugin

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisteredPaths(t *testing.T) {
	b := testBackend(t, nil)
	raw, _ := b.handle("management.register", nil)
	var registration struct {
		Result struct {
			Routes    []struct{ Method, Path string }            `json:"routes"`
			Resources []struct{ Path, Menu, Description string } `json:"resources"`
		}
	}
	if err := json.Unmarshal(raw, &registration); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"/v0/management/plugins/cpa-plugin-set-proxies/state":    "GET",
		"/v0/management/plugins/cpa-plugin-set-proxies/scan":     "POST",
		"/v0/management/plugins/cpa-plugin-set-proxies/cancel":   "POST",
		"/v0/management/plugins/cpa-plugin-set-proxies/apply":    "POST",
		"/v0/management/plugins/cpa-plugin-set-proxies/settings": "POST",
	}
	if len(registration.Result.Routes) != len(want) {
		t.Fatal("incorrect route count")
	}
	for _, r := range registration.Result.Routes {
		if want[r.Path] != r.Method {
			t.Fatalf("unexpected registration %+v", r)
		}
		delete(want, r.Path)
	}
	if len(want) != 0 {
		t.Fatal("missing routes")
	}
	resources := registration.Result.Resources
	if len(resources) != 1 || resources[0].Path != "/v0/resource/plugins/cpa-plugin-set-proxies/ui" || resources[0].Menu != "代理分配" || resources[0].Description == "" {
		t.Fatal("resource metadata missing")
	}
	for _, path := range []string{"/state", "/scan", "/cancel", "/apply", "/settings", base + "/prepare", "/ui", "/v0/management/state", base + "//state", base + "/state/", resource + "/", base + "/../state"} {
		req, _ := json.Marshal(map[string]any{"Method": "GET", "Path": path})
		raw, _ := b.handle("management.handle", req)
		if status(t, raw) != 404 {
			t.Errorf("unregistered path accepted: %s", path)
		}
	}
}
func TestResponseSecurityHeaders(t *testing.T) {
	b := testBackend(t, []any{""})
	scan(t, b)
	for _, tc := range []struct {
		method, path string
		body         any
	}{{"GET", resource, nil}, {"GET", base + "/state", nil}, {"POST", base + "/apply", map[string]string{"plan_id": "invalid-plan"}}, {"GET", "/bad", nil}} {
		body, _ := json.Marshal(tc.body)
		req, _ := json.Marshal(map[string]any{"Method": tc.method, "Path": tc.path, "Body": body})
		raw, _ := b.handle("management.handle", req)
		var env struct{ Result struct{ Headers http.Header } }
		if json.Unmarshal(raw, &env) != nil {
			t.Fatal("invalid envelope")
		}
		h := env.Result.Headers
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("missing security headers: %s", tc.path)
		}
		if tc.path == resource && h.Get("Content-Security-Policy") != "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'" {
			t.Fatal("incorrect CSP")
		}
	}
}
func TestQuiesceRejectsNewScans(t *testing.T) {
	for _, method := range []string{"plugin.quiesce", "plugin.shutdown"} {
		b := testBackend(t, []any{""})
		scan(t, b)
		b.handle(method, nil)
		raw, _ := b.start()
		if status(t, raw) != 503 {
			t.Fatal("scan accepted after stop")
		}
		b.handle("plugin.reconfigure", []byte(`{}`))
		raw, _ = b.start()
		if status(t, raw) != 202 {
			t.Fatal("reconfigure did not reopen scans")
		}
		<-b.finished
	}
}

type brokenRandom struct{}

func (brokenRandom) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }
func TestRandomFailure(t *testing.T) {
	original := rand.Reader
	defer func() { rand.Reader = original }()
	b := testBackend(t, []any{""})
	rand.Reader = brokenRandom{}
	raw, _ := b.start()
	if status(t, raw) != 500 || b.cancel != nil || b.s.PlanID != "" {
		t.Fatal("random failure did not reject scan")
	}
	rand.Reader = original
	fetch := b.fetch
	b.fetch = func(ctx context.Context, s string) ([]node, error) {
		rand.Reader = brokenRandom{}
		return fetch(ctx, s)
	}
	scan(t, b)
	if b.s.Phase != "failed" || b.s.PlanID != "" || len(b.assignments) != 0 {
		t.Fatal("random failure created plan")
	}
}
func TestOversizedDownloadRejected(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.Copy(w, strings.NewReader(strings.Repeat("1", (16<<20)+1)))
	}))
	defer s.Close()
	if _, err := fetchNodes(context.Background(), s.URL); err == nil || err.Error() != "Proxy download exceeds size limit" {
		t.Fatal("oversized proxy list accepted or error misclassified")
	}
}
func TestCredentialPathChange(t *testing.T) {
	b := testBackend(t, []any{""})
	original := b.host
	changed := false
	b.host = func(m string, p any) (json.RawMessage, error) {
		raw, err := original(m, p)
		if m == "host.auth.get" && changed {
			var doc map[string]any
			json.Unmarshal(raw, &doc)
			doc["path"] = "/auth/recreated.json"
			raw, _ = json.Marshal(doc)
		}
		return raw, err
	}
	scan(t, b)
	plan := b.s.PlanID
	changed = true
	raw, _ := b.apply(plan)
	if status(t, raw) != 202 {
		t.Fatal("apply rejected")
	}
	waitTask(t, b)
	if len(b.s.Results) != 1 || b.s.Results[0].Status != "conflict" {
		t.Fatal("different credential accepted")
	}
	scan(t, b)
	if b.s.Phase != "failed" || b.s.PlanID != "" {
		t.Fatal("listing path mismatch accepted")
	}
}
func TestTokenRefreshDoesNotInvalidatePlan(t *testing.T) {
	b := testBackend(t, []any{""})
	original := b.host
	token := "before-refresh"
	b.host = func(method string, payload any) (json.RawMessage, error) {
		raw, err := original(method, payload)
		if method == "host.auth.get" && err == nil {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}
			doc["json"].(map[string]any)["token"] = token
			return json.Marshal(doc)
		}
		return raw, err
	}
	scan(t, b)
	token = "after-refresh"
	raw, err := b.apply(b.s.PlanID)
	if err != nil || status(t, raw) != 202 {
		t.Fatal("token-only refresh invalidated plan")
	}
	waitTask(t, b)
	if len(b.s.Results) != 1 || b.s.Results[0].Status != "success" {
		t.Fatal("token-only refresh invalidated write")
	}
}

func TestConfigurationCredentialsSkipped(t *testing.T) {
	b := testBackend(t, nil)
	b.host = func(m string, _ any) (json.RawMessage, error) {
		if m != "host.auth.list" {
			t.Fatal("configuration credential read")
		}
		return json.Marshal(map[string]any{"files": []entry{{Name: "config.json", Index: "a", Path: "/config.json", Source: "config"}, {Name: "memory.json", Index: "b", Path: "/memory.json", Source: "memory"}, {Name: "runtime.json", Index: "c", Runtime: true}}})
	}
	scan(t, b)
	if b.s.Summary.Excluded != 3 || len(b.assignments) != 0 {
		t.Fatal("configuration credentials not skipped")
	}
}
