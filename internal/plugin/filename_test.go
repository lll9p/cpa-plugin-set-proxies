package plugin

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestCredentialJSONExtensionMatchesCPA(t *testing.T) {
	for _, name := range []string{"a.JSON", "a.Json"} {
		t.Run(name, func(t *testing.T) {
			b := testBackend(t, []any{""})
			b.host = func(method string, _ any) (json.RawMessage, error) {
				if method == "host.auth.list" {
					return json.Marshal(map[string]any{"files": []entry{{Name: name, Index: "a", Path: "/auth/" + name}}})
				}
				return json.Marshal(map[string]any{"path": "/auth/" + name, "json": map[string]any{}})
			}
			applyServer(t, b, func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				if body["name"] != name {
					t.Error("original credential filename was not preserved")
				}
				w.WriteHeader(200)
			})
			scan(t, b)
			if b.s.Summary.Pending != 1 {
				t.Fatal("valid credential extension skipped")
			}
			b.apply(b.s.PlanID)
			waitTask(t, b)
			if len(b.s.Results) != 1 || b.s.Results[0].Status != "success" {
				t.Fatal("valid credential not updated")
			}
			b.cfg.Excludes = []string{name}
			scan(t, b)
			if b.s.Summary.Excluded != 1 || b.s.PlanID != "" {
				t.Fatal("original exclusion filename was not preserved")
			}
		})
	}
}

func TestListenerDoesNotGuessRemoteStoreConfig(t *testing.T) {
	for _, name := range []string{"HOME_JWT", "GITSTORE_GIT_URL", "OBJECTSTORE_ENDPOINT"} {
		for _, key := range []string{name, strings.ToLower(name)} {
			t.Run(key, func(t *testing.T) {
				clearCPAStoreEnv(t)
				old := os.Args
				t.Cleanup(func() { os.Args = old })
				os.Args = []string{"cpa"}
				t.Setenv(key, "private-secret")
				if name == "HOME_JWT" {
					t.Setenv("PGSTORE_DSN", "private-secret")
				}
				_, err := cpaEndpoint()
				mode := "git or object-store"
				if name == "HOME_JWT" {
					mode = "Home"
				}
				if err == nil || !strings.Contains(err.Error(), "does not support "+mode) || strings.Contains(err.Error(), "private-secret") {
					t.Fatalf("remote config guessed, wrong precedence, or secret exposed: %v", err)
				}
			})
		}
	}
}
