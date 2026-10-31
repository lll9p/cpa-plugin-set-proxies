package plugin

import (
	"encoding/json"
	"testing"
)

func TestRequiredRegistrationMetadata(t *testing.T) {
	b := testBackend(t, nil)
	raw, err := b.handle("plugin.register", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		OK     bool `json:"ok"`
		Result struct {
			Schema   int                        `json:"schema_version"`
			Metadata map[string]json.RawMessage `json:"metadata"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || !envelope.OK || envelope.Result.Schema != 6 {
		t.Fatal("invalid registration")
	}
	for name, want := range map[string]string{
		"Name":             "cpa-plugin-set-proxies",
		"Version":          pluginVersion,
		"Author":           "lll9p",
		"GitHubRepository": "https://github.com/lll9p/cpa-plugin-set-proxies",
	} {
		var value string
		if err := json.Unmarshal(envelope.Result.Metadata[name], &value); err != nil || value != want {
			t.Fatalf("metadata %s = %q, want %q (decode error: %v)", name, value, want, err)
		}
	}
}

func TestNoLegacyConfigurationImport(t *testing.T) {
	t.Setenv("WEBSHARE_URL", "https://env.invalid/secret")
	b := testBackend(t, []any{""})
	b.cfg = config{Excludes: []string{}}
	if err := writeSettings(b.settingsPath, b.cfg); err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(map[string]any{"config_yaml": []byte("webshare_url: https://legacy.invalid/secret\nexcludes: [a.json]\n")})
	b.handle("plugin.register", p)
	if b.s.Configured || b.cfg.Key != "" || len(b.cfg.Excludes) != 0 {
		t.Fatal("legacy configuration imported")
	}
	raw, _ := b.start()
	if status(t, raw) != 400 {
		t.Fatal("environment URL used instead of saved settings")
	}
}
