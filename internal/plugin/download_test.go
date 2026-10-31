package plugin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDownloadFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"missing plan", `{"detail":"Plan not found."}`, "Proxy download plan not found", 404},
		{"missing plan without period", `{"detail":"Plan not found"}`, "Proxy download plan not found", 404},
		{"not a plan failure", `{"detail":"Plan not found."}`, "Proxy download HTTP 403", 403},
		{"not found", `{"detail":"Not found."}`, "Proxy download HTTP 404", 404},
		{"secret error body", `{"detail":"private-key https://secret.invalid/private-token"}`, "Proxy download HTTP 404", 404},
		{"malformed detail", `{"detail":123}`, "Proxy download HTTP 404", 404},
		{"oversized error body", strings.Repeat("x", 5000), "Proxy download HTTP 404", 404},
		{"rate limited", "private-key", "Proxy download HTTP 429", 429},
		{"server failure", "private-key", "Proxy download HTTP 503", 503},
		{"empty", " \n\r\n", "Proxy list empty", 200},
		{"HTML", "<html>private-key</html>", "Proxy list format invalid", 200},
		{"JSON", `{"private-key":"private-token"}`, "Proxy list format invalid", 200},
		{"invalid proxies", "host:99999:user:private-password", "Proxy list format invalid", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer s.Close()
			nodes, err := fetchNodes(context.Background(), s.URL+"/private-token")
			if err == nil || err.Error() != tc.want || len(nodes) != 0 {
				t.Fatal("incorrect sanitized download failure")
			}
			b := testBackend(t, []any{""})
			b.fetch = func(ctx context.Context, _ string) ([]node, error) {
				return fetchNodes(ctx, s.URL+"/private-token")
			}
			scan(t, b)
			raw, _ := json.Marshal(b.s)
			if b.s.Phase != "failed" || b.s.Stage != "fetch" || b.s.Error != tc.want ||
				b.s.PlanID != "" || len(b.assignments) != 0 || strings.Contains(string(raw), "private-") {
				t.Fatal("download failure hidden, leaked secrets, or generated a plan")
			}
		})
	}
}

func TestDownloadNetworkFailureRedaction(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "private-password", Name: "private.invalid"}, "Proxy download DNS failed"},
		{&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "Proxy download TLS failed"},
		{context.DeadlineExceeded, "Proxy download timed out"},
		{errors.New("private-password"), "Proxy download network failed"},
	} {
		err := &url.Error{Op: "Get", URL: "https://secret.invalid/private-token", Err: tc.err}
		if got := downloadFailure(err); got.Error() != tc.want {
			t.Fatal("incorrect sanitized network failure")
		}
	}
	b := testBackend(t, nil)
	b.fetch = func(context.Context, string) ([]node, error) {
		return nil, errors.New("https://secret.invalid/private-token")
	}
	scan(t, b)
	if b.s.Error != "Proxy download network failed" {
		t.Fatal("unexpected fetch error leaked or was misclassified")
	}
	if _, err := fetchNodes(context.Background(), "://private-token"); err == nil ||
		err.Error() != "Proxy download request invalid" {
		t.Fatal("invalid request leaked or was misclassified")
	}
}

func TestDownloadTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	nodes, err := fetchNodes(ctx, s.URL+"/private-token")
	if len(nodes) != 0 || err == nil || err.Error() != "Proxy download timed out" {
		t.Fatal("body read timeout hidden or leaked request")
	}
}
