package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordValidationFailuresPreserveSettingsAndPlan(t *testing.T) {
	for _, mode := range []string{"unauthorized", "forbidden", "server-error", "redirect", "timeout", "network", "endpoint", "same-key"} {
		t.Run(mode, func(t *testing.T) {
			b := testBackend(t, []any{""})
			scan(t, b)
			before, _ := os.ReadFile(b.settingsPath)
			oldConfig, _ := json.Marshal(b.cfg)
			oldState, _ := json.Marshal(b.s)
			items := append([]assignment(nil), b.assignments...)
			expires := b.expires
			key := "replacement-secret"
			if mode == "same-key" {
				key = b.cfg.Key
			}
			var requests atomic.Int32
			code, message := 502, "Unable to verify CPA management password"
			applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.URL.Path != "/v0/management/plugins" || r.Header.Get("Authorization") != "Bearer "+key {
					t.Error("unexpected password validation request")
				}
				switch mode {
				case "timeout":
					<-r.Context().Done()
					return
				case "network":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				case "redirect":
					w.Header().Set("Location", "/must-not-follow?private-secret")
					w.WriteHeader(307)
				case "server-error":
					w.WriteHeader(500)
				case "forbidden":
					w.WriteHeader(403)
				default:
					w.WriteHeader(401)
				}
				w.Write([]byte("private-secret"))
			})
			if mode == "timeout" {
				b.client.Timeout = 40 * time.Millisecond
			}
			if mode == "endpoint" {
				b.endpoint = func() (string, error) { return "", errors.New("private-secret") }
				code, message = 500, "Unable to read CPA listener configuration"
			}
			if mode == "unauthorized" || mode == "forbidden" || mode == "same-key" {
				code, message = 422, "CPA management authentication failed"
			}
			raw := managementRequest(t, b, "POST", base+"/settings", map[string]any{"management_key": key, "webshare_url": "https://example.com/new", "excludes": []string{"new.json"}}, nil)
			if status(t, raw) != code || string(responseBody(t, raw)) != `{"error":"`+message+`"}` {
				t.Fatalf("unexpected validation failure: %s", raw)
			}
			after, _ := os.ReadFile(b.settingsPath)
			cfg, _ := json.Marshal(b.cfg)
			state, _ := json.Marshal(b.s)
			if !bytes.Equal(before, after) || !bytes.Equal(oldConfig, cfg) || !bytes.Equal(oldState, state) || !reflect.DeepEqual(items, b.assignments) || !expires.Equal(b.expires) {
				t.Fatal("validation failure changed settings or plan")
			}
			want := int32(1)
			if mode == "endpoint" {
				want = 0
			}
			if requests.Load() != want {
				t.Fatal("validation skipped or redirected")
			}
		})
	}
}

func TestPasswordValidationDoesNotBlockState(t *testing.T) {
	b := testBackend(t, nil)
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(200)
	})
	saved := make(chan []byte, 1)
	go func() { raw, _ := b.saveSettings([]byte(`{"management_key":"new-secret"}`)); saved <- raw }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("validation not started")
	}
	state := make(chan []byte, 1)
	go func() { state <- managementRequest(t, b, "GET", base+"/state", nil, nil) }()
	select {
	case raw := <-state:
		if status(t, raw) != 200 {
			t.Fatal("state failed")
		}
	case <-time.After(time.Second):
		t.Fatal("state blocked by password validation")
	}
	close(release)
	select {
	case raw := <-saved:
		if status(t, raw) != 200 {
			t.Fatal("save failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("save did not finish")
	}
}

func TestPasswordValidationRejectsActiveTaskBeforeNetwork(t *testing.T) {
	b := testBackend(t, nil)
	b.fetch = func(ctx context.Context, _ string) ([]node, error) { <-ctx.Done(); return nil, ctx.Err() }
	b.start()
	b.endpoint = func() (string, error) { t.Error("active task attempted password validation"); return "", nil }
	raw, _ := b.saveSettings([]byte(`{"management_key":"new-secret"}`))
	if status(t, raw) != 409 {
		t.Fatal("settings accepted during active task")
	}
	b.cancelTask()
}

func TestSettingsRequireInitialPassword(t *testing.T) {
	b := testBackend(t, nil)
	b.cfg.Key = ""
	b.endpoint = func() (string, error) { t.Error("missing password attempted validation"); return "", nil }
	for _, body := range []any{map[string]any{}, map[string]any{"management_key": "   "}} {
		raw := managementRequest(t, b, "POST", base+"/settings", body, http.Header{"Authorization": {"Bearer ignored"}, "X-Management-Key": {"ignored"}})
		if status(t, raw) != 400 || string(responseBody(t, raw)) != `{"error":"Invalid settings or missing management key"}` {
			t.Fatal("missing password accepted")
		}
	}
}
