package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"time"
)

type applyResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func managementClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (b *backend) apply(plan string) ([]byte, error) {
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
	if plan == "" || plan != b.s.PlanID || b.s.Phase != "ready" || time.Now().After(b.expires) || len(b.assignments) == 0 {
		return response(409, map[string]string{"error": "Plan unavailable or expired"})
	}
	if b.cfg.Key == "" {
		return response(400, map[string]string{"error": "Save settings before applying"})
	}
	endpoint, err := b.endpoint()
	if err != nil {
		return response(500, map[string]string{"error": "Unable to read CPA listener configuration"})
	}
	items := b.assignments
	b.assignments = nil
	b.s.PlanID = ""
	b.s.Phase, b.s.Stage = "applying", "write"
	b.s.Done, b.s.Total = 0, len(items)
	b.s.Error, b.s.Results = "", []applyResult{}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.finished = make(chan struct{})
	go b.runApply(ctx, items, endpoint, b.cfg.Key, b.finished)
	return response(202, map[string]string{"task_id": plan})
}

func (b *backend) runApply(ctx context.Context, items []assignment, endpoint, key string, finished chan struct{}) {
	var failure string
	defer func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.s.Phase, b.s.Stage, b.s.Error = "completed", "complete", failure
		if ctx.Err() != nil {
			b.s.Phase = "cancelled"
		} else if failure != "" {
			b.s.Phase = "failed"
		}
		b.cancel = nil
		close(finished)
	}()
	failure = b.applyItems(ctx, items, endpoint, key)
}

func (b *backend) applyItems(ctx context.Context, items []assignment, endpoint, key string) (failure string) {
	for _, item := range items {
		if ctx.Err() != nil {
			return
		}
		result := applyResult{Name: item.Name}
		current, path, err := b.read(item.Index)
		stop := false
		switch {
		case err != nil:
			result.Status, result.Message = "failed", "Credential read failed"
		case path == "" || filepath.Clean(path) != item.Path || filepath.Base(path) != item.Name:
			result.Status, result.Message = "conflict", "Credential file changed; scan again"
		case current != item.Expected:
			result.Status, result.Message = "conflict", "Proxy setting changed; scan again"
		default:
			if ctx.Err() != nil {
				return
			}
			result, stop = b.patch(endpoint, key, item)
		}
		b.mu.Lock()
		b.s.Results = append(b.s.Results, result)
		b.s.Done++
		b.mu.Unlock()
		if stop {
			failure = result.Message
			return
		}
	}
	return
}

func (b *backend) patch(endpoint, key string, item assignment) (applyResult, bool) {
	result := applyResult{Name: item.Name}
	body, _ := json.Marshal(map[string]string{"name": item.Name, "proxy_url": item.Proxy})
	// Do not abort an in-flight write on cancellation: its outcome must be recorded.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "PATCH", endpoint+"/v8/management/credentials/fields", bytes.NewReader(body))
	if err != nil {
		result.Status, result.Message = "failed", "Invalid CPA listener configuration"
		return result, true
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	res, err := b.client.Do(req)
	if err != nil {
		result.Status, result.Message = "unknown", "Write result uncertain; scan again"
		return result, true
	}
	defer res.Body.Close()
	// Ignore response contents; management errors may contain sensitive values.
	io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		result.Status, result.Message = "success", "Updated"
	case res.StatusCode == 401 || res.StatusCode == 403:
		result.Status, result.Message = "failed", "CPA management authentication failed"
		return result, true
	case res.StatusCode >= 500:
		result.Status, result.Message = "unknown", "Write result uncertain; scan again"
		return result, true
	case res.StatusCode == 409:
		result.Status, result.Message = "conflict", "Proxy setting changed; scan again"
	case res.StatusCode == 429:
		result.Status, result.Message = "failed", "CPA management rate limit reached"
		return result, true
	case res.StatusCode >= 300 && res.StatusCode < 400:
		result.Status, result.Message = "failed", "CPA management redirect refused"
		return result, true
	default:
		result.Status, result.Message = "failed", "CPA update rejected"
	}
	return result, false
}
