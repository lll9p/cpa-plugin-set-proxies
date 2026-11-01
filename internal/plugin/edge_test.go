package plugin

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestManagementValidation(t *testing.T) {
	b := testBackend(t, nil)
	for _, tc := range []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/scan", "{}", 405}, {"POST", "/state", "{}", 405},
		{"GET", "/apply", "{}", 405}, {"GET", "/cancel", "{}", 405}, {"GET", "/settings", "{}", 405},
		{"POST", "/scan", "null", 400}, {"POST", "/scan", "{", 400},
		{"POST", "/apply", "null", 400}, {"POST", "/apply", "[]", 400},
		{"POST", "/apply", "{}", 409}, {"GET", "/unknown", "", 404},
		{"POST", "/settings", "{}", 200}, {"POST", "/cancel", "null", 400},
	} {
		r, _ := json.Marshal(map[string]any{"Method": tc.method, "Path": base + tc.path, "Body": []byte(tc.body)})
		raw, _ := b.handle("management.handle", r)
		if status(t, raw) != tc.code {
			t.Errorf("%s %s: expected %d, got %s", tc.method, tc.path, tc.code, raw)
		}
	}
}
func TestLifecycleLoadsOnlySavedSettings(t *testing.T) {
	b := testBackend(t, []any{""})
	b.cfg.Excludes = []string{"a.json"}
	if err := writeSettings(b.settingsPath, b.cfg); err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(map[string]any{"config_yaml": []byte("enabled: true\n")})
	raw, e := b.handle("plugin.register", p)
	if e != nil || !json.Valid(raw) || !b.s.Configured {
		t.Fatal("registration failed")
	}
	scan(t, b)
	if len(b.assignments) != 0 || b.s.PlanID != "" {
		t.Fatal("saved exclusion ignored or empty plan created")
	}
	raw, _ = b.saveSettings([]byte(`{"excludes":[]}`))
	if status(t, raw) != 200 {
		t.Fatal("settings save failed")
	}
	scan(t, b)
	if len(b.assignments) != 1 {
		t.Fatal("explicit empty excludes ignored")
	}
	plan := b.s.PlanID
	b.handle("plugin.reconfigure", p)
	raw, _ = b.apply(plan)
	if status(t, raw) != 409 {
		t.Fatal("old plan survived reconfiguration")
	}
}
func TestNoAliveAndDedup(t *testing.T) {
	b := testBackend(t, []any{""})
	b.probe = func(context.Context, node) bool { return false }
	scan(t, b)
	if b.s.Phase != "failed" || b.s.PlanID != "" {
		t.Fatal("dead nodes generated plan")
	}
	for _, probe := range b.s.Probes {
		if !probe.Checked || probe.Alive || probe.Attempts != 3 || probe.Category != "unknown" {
			t.Fatalf("incomplete failed probe: %+v", probe)
		}
	}
	b.probe = func(context.Context, node) bool { return true }
	n := node{"host", "1080", "u", "p"}
	b.fetch = func(context.Context, string) ([]node, error) { return []node{n, n}, nil }
	scan(t, b)
	if b.s.Summary.Alive != 1 {
		t.Fatal("endpoint not deduplicated")
	}
	if len(b.s.Probes) != 2 {
		t.Fatal("duplicate endpoints lost their individual probe results")
	}
	for _, probe := range b.s.Probes {
		if !probe.Checked || !probe.Alive || probe.Attempts != 1 || probe.Endpoint != n.endpoint() {
			t.Fatalf("invalid successful probe: %+v", probe)
		}
	}
}
func TestProbeCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if probeNode(ctx, node{"127.0.0.1", "1", "u", "p"}) {
		t.Fatal("cancelled probe succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled probe blocked")
	}
}
func TestCancelReadyPlan(t *testing.T) {
	b := testBackend(t, []any{""})
	scan(t, b)
	plan := b.s.PlanID
	b.cancelTask()
	if b.s.Phase != "cancelled" || b.s.PlanID != "" || len(b.assignments) != 0 {
		t.Fatal("cancel left a ready plan")
	}
	raw, _ := b.apply(plan)
	if status(t, raw) != 409 {
		t.Fatal("cancelled plan applied")
	}
}
func TestEmptyCredentialsDoNotClaimExternalProxy(t *testing.T) {
	b := testBackend(t, []any{"socks5://external:1080"})
	b.fetch = func(context.Context, string) ([]node, error) {
		return []node{{Host: "pool", Port: "1080"}}, nil
	}
	scan(t, b)
	if b.s.Summary.External != 1 || len(b.assignments) != 0 || b.s.PlanID != "" {
		t.Fatal("empty authentication claimed an external proxy")
	}
}
func TestAmbiguousCredentialFilename(t *testing.T) {
	b := testBackend(t, []any{"", ""})
	original := b.host
	b.host = func(method string, p any) (json.RawMessage, error) {
		if method == "host.auth.list" {
			return json.Marshal(map[string]any{"files": []entry{{Name: "a.json", Index: "a", Path: "/auth/a.json"}, {Name: "a.json", Index: "b", Path: "/other/a.json"}}})
		}
		raw, err := original(method, p)
		if method == "host.auth.get" && p.(map[string]string)["auth_index"] == "b" {
			var doc map[string]any
			json.Unmarshal(raw, &doc)
			doc["path"] = "/other/a.json"
			return json.Marshal(doc)
		}
		return raw, err
	}
	scan(t, b)
	if b.s.Phase != "failed" || b.s.PlanID != "" || len(b.assignments) != 0 {
		t.Fatal("ambiguous HTTP filename accepted")
	}
}
