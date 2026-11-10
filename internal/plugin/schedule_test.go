package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func awaitSchedule(t *testing.T, b *backend, check func(state) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		ok := check(b.s)
		b.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("scheduler timeout")
}

func enableSchedule(t *testing.T, b *backend, method string) {
	t.Helper()
	b.cfg.AutoIntervalMinutes = 5
	b.startupDelay = 5 * time.Millisecond
	b.interval = func(int) time.Duration { return 15 * time.Millisecond }
	if err := writeSettings(b.settingsPath, b.cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := b.handle(method, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestAutoIntervalSettings(t *testing.T) {
	for _, value := range []string{"-1", "1", "4", "1441", "null", `"5"`, "5.5"} {
		t.Run(value, func(t *testing.T) {
			b := testBackend(t, nil)
			raw, _ := b.saveSettings([]byte(`{"auto_interval_minutes":` + value + `}`))
			if status(t, raw) != 400 {
				t.Fatalf("accepted %s", value)
			}
		})
	}
	for _, n := range []int{0, 5, 1440} {
		b := testBackend(t, nil)
		body, _ := json.Marshal(map[string]int{"auto_interval_minutes": n})
		raw, _ := b.saveSettings(body)
		if status(t, raw) != 200 {
			t.Fatalf("rejected %d: %s", n, raw)
		}
		raw, _ = b.saveSettings([]byte(`{"excludes":["a.json"]}`))
		if status(t, raw) != 200 || b.cfg.AutoIntervalMinutes != n {
			t.Fatal("omitted interval not preserved")
		}
		raw, _ = b.saveSettings([]byte(`{"management_key":"replacement"}`))
		if status(t, raw) != 200 || b.cfg.AutoIntervalMinutes != n {
			t.Fatal("password save changed interval")
		}
		raw, _ = b.saveSettings([]byte(`{"clear_webshare_url":true}`))
		if status(t, raw) != 200 || b.cfg.AutoIntervalMinutes != 0 || b.schedCancel != nil || b.s.NextCheckAt != "" {
			t.Fatal("clear did not disable scheduler")
		}
	}
	for _, missing := range []string{"url", "key"} {
		b := testBackend(t, nil)
		if missing == "url" {
			b.cfg.URL = ""
		} else {
			b.cfg.Key = ""
		}
		raw, _ := b.saveSettings([]byte(`{"auto_interval_minutes":5}`))
		if status(t, raw) != 400 {
			t.Fatal("accepted incomplete configuration")
		}
	}
}

func TestSchedulerLifecycleAndHealthyProxy(t *testing.T) {
	for _, method := range []string{"plugin.register", "plugin.reconfigure"} {
		t.Run(method, func(t *testing.T) {
			values := []any{""}
			b := testBackend(t, values)
			var patches atomic.Int32
			// Serialize the fixture's credential reads with simulated writes.
			original := b.host
			var current atomic.Value
			current.Store("")
			b.host = func(method string, p any) (json.RawMessage, error) {
				if method == "host.auth.get" {
					return json.Marshal(map[string]any{"path": "/auth/a.json", "json": map[string]string{"proxy_url": current.Load().(string)}})
				}
				return original(method, p)
			}
			applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" {
					b.mu.Lock()
					if b.s.PlanID != "" || b.s.Phase != "applying" {
						t.Error("automatic write exposed preview")
					}
					if b.nextCheckAt != "" || b.s.NextCheckAt != "" {
						t.Error("automatic write retained past schedule time")
					}
					b.mu.Unlock()
					var body struct {
						Proxy string `json:"proxy_url"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					current.Store(body.Proxy)
					patches.Add(1)
				}
				w.WriteHeader(200)
			})
			enableSchedule(t, b, method)
			awaitSchedule(t, b, func(s state) bool {
				return s.Phase == "completed" && len(s.Results) == 1 && s.LastCheckAt != "" && s.NextCheckAt != "" && s.PlanID == ""
			})
			awaitSchedule(t, b, func(s state) bool {
				return s.Phase == "completed" && s.Summary.Kept == 1 && s.Summary.Pending == 0 && len(s.Results) == 0
			})
			if patches.Load() != 1 {
				t.Fatal("healthy credential rewritten")
			}
			b.handle("plugin.shutdown", []byte(`{}`))
			b.mu.Lock()
			if b.cancel != nil || b.schedCancel != nil || b.nextCheckAt != "" {
				t.Error("shutdown left work active")
			}
			b.mu.Unlock()
		})
	}
}

func TestSchedulerFailuresRecover(t *testing.T) {
	for _, failure := range []string{"Proxy download network failed", "Proxy download plan not found", "Proxy list empty", "No live proxies"} {
		t.Run(failure, func(t *testing.T) {
			b := testBackend(t, []any{""})
			var recoverNow atomic.Bool
			var patches atomic.Int32
			fetch := b.fetch
			b.fetch = func(ctx context.Context, url string) ([]node, error) {
				if !recoverNow.Load() && failure != "No live proxies" {
					return nil, downloadError(failure)
				}
				return fetch(ctx, url)
			}
			b.probe = func(context.Context, node) bool { return failure != "No live proxies" || recoverNow.Load() }
			applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" {
					patches.Add(1)
				}
				w.WriteHeader(200)
			})
			enableSchedule(t, b, "plugin.register")
			awaitSchedule(t, b, func(s state) bool { return s.Phase == "failed" && s.Error == failure && s.LastCheckAt != "" })
			if patches.Load() != 0 {
				t.Fatal("write after failed scan")
			}
			recoverNow.Store(true)
			awaitSchedule(t, b, func(s state) bool { return s.Phase == "completed" && len(s.Results) == 1 })
		})
	}
}

func TestSchedulerRespectsManualPlan(t *testing.T) {
	b := testBackend(t, []any{""})
	b.cfg.AutoIntervalMinutes = 5
	scan(t, b)
	b.mu.Lock()
	plan := b.s.PlanID
	b.mu.Unlock()
	if ch := b.tryStartAuto(); ch != nil {
		t.Fatal("overwrote manual preview")
	}
	b.mu.Lock()
	if b.s.PlanID != plan {
		t.Error("manual plan changed")
	}
	b.mu.Unlock()
}

func TestSchedulerCancelAndQuiesce(t *testing.T) {
	b := testBackend(t, nil)
	var starts atomic.Int32
	b.fetch = func(ctx context.Context, _ string) ([]node, error) {
		starts.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	enableSchedule(t, b, "plugin.register")
	awaitSchedule(t, b, func(s state) bool { return starts.Load() > 0 && s.Phase == "scanning" })
	b.mu.Lock()
	if b.nextCheckAt != "" || b.s.NextCheckAt != "" {
		t.Error("automatic scan retained past schedule time")
	}
	b.mu.Unlock()
	if ch := b.tryStartAuto(); ch != nil {
		t.Fatal("started overlapping task")
	}
	b.cancelTask()
	b.mu.Lock()
	enabled := b.cfg.AutoIntervalMinutes == 5 && b.schedCancel != nil
	b.mu.Unlock()
	if !enabled {
		t.Fatal("cancel disabled scheduler")
	}
	awaitSchedule(t, b, func(s state) bool { return starts.Load() > 1 && s.Phase == "scanning" })
	b.handle("plugin.quiesce", []byte(`{}`))
	n := starts.Load()
	time.Sleep(35 * time.Millisecond)
	if starts.Load() != n {
		t.Fatal("scheduler survived quiesce")
	}
}
