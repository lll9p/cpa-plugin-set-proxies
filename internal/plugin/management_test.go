package plugin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func managementRequest(t *testing.T, b *backend, method, path string, body any, headers http.Header) []byte {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := json.Marshal(map[string]any{"Method": method, "Path": path, "Body": data, "Headers": headers})
	raw, err := b.handle("management.handle", req)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func responseBody(t *testing.T, raw []byte) []byte {
	t.Helper()
	var envelope struct{ Result struct{ Body []byte } }
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Result.Body
}

func TestSettingsAPIAndRestart(t *testing.T) {
	b := testBackend(t, []any{""})
	scan(t, b)
	oldPlan := b.s.PlanID
	previous := b.s
	header := http.Header{"Authorization": {"Bearer saved-secret"}}
	raw := managementRequest(t, b, "POST", base+"/settings", map[string]any{"management_key": " saved-secret ", "webshare_url": " https://example.com/private-url ", "excludes": []string{" a.json ", " ", "b.json"}}, header)
	if status(t, raw) != 200 || b.cfg.URL != "https://example.com/private-url" || b.cfg.Key != "saved-secret" || strings.Join(b.cfg.Excludes, ",") != "a.json,b.json" || b.s.PlanID != "" {
		t.Fatalf("settings not saved or plan not invalidated: %+v", b.s)
	}
	if !b.s.PreviewStale || len(b.s.Rows) != len(previous.Rows) || b.s.Summary != previous.Summary || len(b.s.Probes) != len(previous.Probes) || !b.expires.IsZero() || len(b.assignments) != 0 {
		t.Fatal("settings change did not retain an unappliable preview")
	}
	if strings.Contains(string(responseBody(t, raw)), "saved-secret") || strings.Contains(string(responseBody(t, raw)), "private-url") {
		t.Fatal("settings response leaked secrets")
	}
	raw, _ = b.apply(oldPlan)
	if status(t, raw) != 409 {
		t.Fatal("settings change left old plan usable")
	}
	// Blank URL preserves it; only an explicit password change rotates the key.
	raw = managementRequest(t, b, "POST", base+"/settings", map[string]any{"webshare_url": "", "management_key": "rotated-secret"}, nil)
	if status(t, raw) != 200 || b.cfg.Key != "rotated-secret" || b.cfg.URL != "https://example.com/private-url" || len(b.cfg.Excludes) != 2 {
		t.Fatal("blank update lost saved settings")
	}
	restarted := testBackend(t, nil)
	restarted.settingsPath = b.settingsPath
	raw, _ = restarted.handle("plugin.register", []byte(`{}`))
	var registration struct{ OK bool }
	json.Unmarshal(raw, &registration)
	if !registration.OK || restarted.cfg.Key != "rotated-secret" || !restarted.s.KeySet || !restarted.s.Configured || restarted.s.Phase != "idle" || restarted.s.PlanID != "" || restarted.s.PreviewStale || len(restarted.s.Probes) != 0 {
		t.Fatal("restart failed to restore settings or restored a stale plan")
	}
	state := managementRequest(t, restarted, "GET", base+"/state", nil, header)
	page := managementRequest(t, restarted, "GET", resource, nil, nil)
	for _, result := range [][]byte{responseBody(t, state), responseBody(t, page)} {
		if bytes.Contains(result, []byte("rotated-secret")) || bytes.Contains(result, []byte("private-url")) {
			t.Fatal("secret leaked into state or public UI")
		}
	}
	raw = managementRequest(t, b, "POST", base+"/settings", map[string]any{"clear_webshare_url": true}, header)
	if status(t, raw) != 200 || b.cfg.URL != "" || b.s.Configured {
		t.Fatal("explicit clear did not clear URL")
	}
	b.handle("plugin.reconfigure", []byte(`{}`))
	if b.cfg.URL != "" {
		t.Fatal("cleared URL returned after reload")
	}
}

func TestExplicitManagementKeyPreservesSettings(t *testing.T) {
	b := testBackend(t, nil)
	b.cfg.Key = "old-secret"
	b.cfg.Excludes = []string{"saved.json"}
	oldURL := b.cfg.URL
	header := http.Header{"Authorization": {"Bearer current-cpa-secret"}, "X-Management-Key": {"another-secret"}}
	managementRequest(t, b, "GET", base+"/state", nil, header)
	if b.cfg.Key != "old-secret" {
		t.Fatal("viewing state rotated the saved key")
	}
	b.endpoint = func() (string, error) { t.Fatal("ordinary save attempted validation"); return "", nil }
	for _, body := range []any{map[string]any{}, map[string]any{"management_key": "   "}} {
		raw := managementRequest(t, b, "POST", base+"/settings", body, header)
		if status(t, raw) != 200 || b.cfg.Key != "old-secret" {
			t.Fatal("headers or blank password rotated the saved key")
		}
	}
	applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/management/plugins" || r.Header.Get("Authorization") != "Bearer current-cpa-secret" {
			t.Error("unexpected password validation request")
		}
		w.WriteHeader(204)
	})
	raw := managementRequest(t, b, "POST", base+"/settings", map[string]any{"management_key": "current-cpa-secret"}, header)
	if status(t, raw) != 200 || b.cfg.Key != "current-cpa-secret" || b.cfg.URL != oldURL || strings.Join(b.cfg.Excludes, ",") != "saved.json" {
		t.Fatal("explicit password change altered other settings")
	}
	if strings.Contains(string(responseBody(t, raw)), "current-cpa-secret") || strings.Contains(string(responseBody(t, raw)), oldURL) {
		t.Fatal("explicit password change leaked secrets")
	}
}

func TestSettingsRejectInvalidInputsWithoutChanges(t *testing.T) {
	b := testBackend(t, []any{""})
	scan(t, b)
	plan, oldKey, oldURL := b.s.PlanID, b.cfg.Key, b.cfg.URL
	header := http.Header{"Authorization": {"Bearer replacement-secret"}}
	b.endpoint = func() (string, error) { t.Fatal("invalid input attempted validation"); return "", nil }
	before, _ := os.ReadFile(b.settingsPath)
	for _, body := range []any{
		map[string]any{"management_key": nil},
		map[string]any{"management_key": 123},
		map[string]any{"management_key": []string{"secret"}},
		map[string]any{"management_key": "\r\nsecret"},
		map[string]any{"webshare_url": "invalid", "management_key": "replacement-secret"},
		map[string]any{"webshare_url": "https://example.com/new", "clear_webshare_url": true},
		map[string]any{"excludes": "not-an-array"},
		map[string]any{"webshare_url": "https://example.com/" + strings.Repeat("x", maxSettingsSize)},
	} {
		raw := managementRequest(t, b, "POST", base+"/settings", body, header)
		if status(t, raw) != 400 || b.cfg.Key != oldKey || b.cfg.URL != oldURL || b.s.PlanID != plan {
			t.Fatal("invalid settings changed configuration or plan")
		}
		after, _ := os.ReadFile(b.settingsPath)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid input changed settings file")
		}
	}
	b.settingsPath = t.TempDir()
	raw := managementRequest(t, b, "POST", base+"/settings", map[string]any{"webshare_url": "https://example.com/new"}, header)
	if status(t, raw) != 500 || b.cfg.Key != oldKey || b.cfg.URL != oldURL || b.s.PlanID != plan {
		t.Fatal("failed save changed in-memory settings or plan")
	}
}

func TestCorruptSettingsStopRegistration(t *testing.T) {
	b := testBackend(t, nil)
	contents := []byte(`{"management_key":"private-secret`)
	if err := os.WriteFile(b.settingsPath, contents, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := b.handle("plugin.register", []byte(`{}`))
	var registration struct{ OK bool }
	json.Unmarshal(raw, &registration)
	if registration.OK || strings.Contains(string(raw), "private-secret") {
		t.Fatal("corrupt settings accepted or exposed")
	}
	after, _ := os.ReadFile(b.settingsPath)
	if !bytes.Equal(after, contents) || !b.quiesced {
		t.Fatal("corrupt settings silently replaced")
	}
}
