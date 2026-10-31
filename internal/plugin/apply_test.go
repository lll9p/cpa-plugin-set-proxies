package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func applyServer(t *testing.T, b *backend, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	b.endpoint = func() (string, error) { return server.URL, nil }
}

func TestBackendPatchFieldsAndSingleUse(t *testing.T) {
	b := testBackend(t, []any{"", ""})
	requests := make(chan map[string]string, 2)
	applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.URL.Path != "/v8/management/credentials/fields" || r.Header.Get("Authorization") != "Bearer management-secret" {
			t.Error("unexpected management request")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["name"] == "" || body["proxy_url"] == "" {
			t.Error("PATCH must contain only name and proxy_url")
		}
		requests <- body
		w.WriteHeader(200)
	})
	scan(t, b)
	plan := b.s.PlanID
	want := append([]assignment(nil), b.assignments...)
	raw, _ := b.apply(plan)
	if status(t, raw) != 202 {
		t.Fatal("apply rejected")
	}
	// No browser requests are needed to drive the task after this point.
	waitTask(t, b)
	if b.s.Phase != "completed" || b.s.PlanID != "" || b.s.Done != 2 || len(b.assignments) != 0 {
		t.Fatalf("incomplete state: %+v", b.s)
	}
	for _, item := range want {
		body := <-requests
		if body["name"] != item.Name || body["proxy_url"] != item.Proxy {
			t.Fatal("assignment changed")
		}
	}
	raw, _ = b.apply(plan)
	if status(t, raw) != 409 {
		t.Fatal("plan applied twice")
	}
}

func TestBackendChecksEachItemImmediatelyBeforeWrite(t *testing.T) {
	values := []any{"", ""}
	b := testBackend(t, values)
	var writes atomic.Int32
	applyServer(t, b, func(w http.ResponseWriter, _ *http.Request) {
		writes.Add(1)
		w.WriteHeader(200)
	})
	original := b.host
	b.host = func(method string, p any) (json.RawMessage, error) {
		if method == "host.auth.get" && p.(map[string]string)["auth_index"] == "b" && writes.Load() > 0 {
			return json.Marshal(map[string]any{"path": "/auth/b.json", "json": map[string]any{"proxy_url": "direct"}})
		}
		return original(method, p)
	}
	scan(t, b)
	b.apply(b.s.PlanID)
	waitTask(t, b)
	if writes.Load() != 1 || len(b.s.Results) != 2 || b.s.Results[0].Status != "success" || b.s.Results[1].Status != "conflict" {
		t.Fatalf("per-item conflict was not protected: %+v", b.s.Results)
	}
}

func TestBackendWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		name, firstStatus, phase string
		code, count              int
	}{
		{"rejected", "failed", "completed", 400, 2},
		{"conflict", "conflict", "completed", 409, 2},
		{"unauthorized", "failed", "failed", 401, 1},
		{"forbidden", "failed", "failed", 403, 1},
		{"rate-limit", "failed", "failed", 429, 1},
		{"server-error", "unknown", "failed", 500, 1},
		{"redirect", "failed", "failed", 307, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := testBackend(t, []any{"", ""})
			var writes atomic.Int32
			applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
				if writes.Add(1) == 1 {
					w.Header().Set("Location", "/must-not-follow")
					w.WriteHeader(tc.code)
					w.Write([]byte("private-key and proxy-password"))
					return
				}
				if r.URL.Path != "/v8/management/credentials/fields" {
					t.Error("redirect followed")
				}
				w.WriteHeader(200)
			})
			scan(t, b)
			b.apply(b.s.PlanID)
			waitTask(t, b)
			if writes.Load() != int32(tc.count) || b.s.Phase != tc.phase || len(b.s.Results) != tc.count || b.s.Results[0].Status != tc.firstStatus {
				t.Fatalf("incorrect outcome: %+v", b.s)
			}
			raw, _ := json.Marshal(b.s)
			if strings.Contains(string(raw), "private-key") || strings.Contains(string(raw), "proxy-password") {
				t.Fatal("response contents leaked")
			}
		})
	}
}

func TestBackendUncertainWriteDoesNotRetry(t *testing.T) {
	b := testBackend(t, []any{"", ""})
	var writes atomic.Int32
	applyServer(t, b, func(w http.ResponseWriter, _ *http.Request) {
		writes.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		connection.Close()
	})
	scan(t, b)
	plan := b.s.PlanID
	b.apply(plan)
	waitTask(t, b)
	if writes.Load() != 1 || b.s.Phase != "failed" || len(b.s.Results) != 1 || b.s.Results[0].Status != "unknown" {
		t.Fatalf("uncertain write retried or concealed: %+v", b.s)
	}
	raw, _ := b.apply(plan)
	if status(t, raw) != 409 {
		t.Fatal("uncertain plan reused")
	}
}

func TestBackendCancellationWaitsForInFlightWrite(t *testing.T) {
	b := testBackend(t, []any{"", ""})
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var writes atomic.Int32
	applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
		if writes.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				t.Error("in-flight PATCH was cancelled")
			}
		}
		w.WriteHeader(200)
	})
	scan(t, b)
	plan := b.s.PlanID
	b.apply(plan)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not start")
	}
	raw, _ := b.start()
	if status(t, raw) != 409 {
		t.Fatal("parallel scan accepted")
	}
	raw, _ = b.apply(plan)
	if status(t, raw) != 409 {
		t.Fatal("parallel apply accepted")
	}
	raw, _ = b.saveSettings([]byte(`{"management_key":"replacement-secret"}`))
	if status(t, raw) != 409 {
		t.Fatal("settings changed during a task")
	}
	cancelled := make(chan struct{})
	go func() { b.cancelTask(); close(cancelled) }()
	deadline := time.After(3 * time.Second)
	for {
		b.mu.Lock()
		stopping := b.s.Phase == "cancelling"
		b.mu.Unlock()
		if stopping {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cancellation did not start")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-cancelled:
		t.Fatal("cancellation completed before the write")
	default:
	}
	close(release)
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not finish")
	}
	if writes.Load() != 1 || b.s.Phase != "cancelled" || b.s.Done != 1 || b.s.Results[0].Status != "success" {
		t.Fatalf("incorrect cancellation result: %+v", b.s)
	}
}

func TestBackendListenerErrorDoesNotConsumePlan(t *testing.T) {
	b := testBackend(t, []any{""})
	scan(t, b)
	plan := b.s.PlanID
	b.endpoint = func() (string, error) { return "", errors.New("secret config contents") }
	raw, _ := b.apply(plan)
	if status(t, raw) != 500 || b.s.PlanID != plan || b.cancel != nil || strings.Contains(string(raw), "secret config") {
		t.Fatal("listener failure concealed or consumed plan")
	}
}
