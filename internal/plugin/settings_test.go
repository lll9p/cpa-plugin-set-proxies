package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "settings.json")
	missing, err := loadSettings(path)
	if err != nil || missing.Excludes == nil || missing.URL != "" || missing.Key != "" {
		t.Fatalf("missing: %#v %v", missing, err)
	}
	want := config{URL: "https://example.com/download/secret?token=private", Key: "private-key", Excludes: []string{"a.json"}}
	for _, key := range []string{"private-key", "replacement-key"} {
		want.Key = key
		if err := writeSettings(path, want); err != nil {
			t.Fatal(err)
		}
		got, err := loadSettings(path)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip: %#v %v", got, err)
		}
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{dir: 0700, path: 0600} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != want {
				t.Fatalf("permissions %s: %v %v", p, info, err)
			}
		}
	}
	if err := writeSettings(path, config{}); err != nil {
		t.Fatal(err)
	}
	got, err := loadSettings(path)
	if err != nil || got.Excludes == nil {
		t.Fatalf("empty excludes: %#v %v", got, err)
	}
}

func TestInvalidSettings(t *testing.T) {
	secret := "do-not-disclose"
	path := filepath.Join(t.TempDir(), "settings.json")
	for _, raw := range []string{
		"{\"management_key\":\"" + secret,
		`null`, `[]`,
		`{"webshare_url":"ftp://` + secret + `"}`,
		`{"webshare_url":"https://` + secret + `@example.com"}`,
		`{"management_key":"` + secret + `\r\n"}`,
		`{"excludes":["` + strings.Repeat("x", maxSettingsSize) + `"]}`,
	} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadSettings(path)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("unsanitized or missing error: %v", err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != raw {
			t.Fatal("load changed corrupt settings")
		}
	}
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if c, err := loadSettings(path); err != nil || c.Excludes == nil {
		t.Fatalf("empty settings: %#v %v", c, err)
	}
	for _, c := range []config{
		{URL: "https://" + secret + "@example.com"},
		{URL: "https://example.com/" + secret + "\n"},
		{Key: secret + "\r"},
		{Key: strings.Repeat(secret, maxSettingsSize)},
	} {
		err := writeSettings(path, c)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("unsanitized or missing error: %v", err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != `{}` {
			t.Fatal("invalid save overwrote settings")
		}
	}
}

func TestSettingsSaveFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "private-secret")
	if err := os.WriteFile(blocker, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(blocker, "settings.json"), dir} {
		err := writeSettings(path, config{Key: "private-secret"})
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("save error: %v", err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".settings-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files leaked: %v %v", matches, err)
	}
	for _, path := range []string{filepath.Join(blocker, "settings.json"), filepath.Join(blocker, "missing", "settings.json")} {
		if _, err := loadSettings(path); err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("read error: %v", err)
		}
	}
	missing, err := loadSettings(filepath.Join(dir, "missing", "nested", "settings.json"))
	if err != nil || missing.Excludes == nil {
		t.Fatalf("missing directories: %#v %v", missing, err)
	}
}

func TestCPAConfigPath(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "config.yaml"},
		{[]string{"-password", "secret", "--config=custom.yaml"}, "custom.yaml"},
		{[]string{"-config", "custom.yaml"}, "custom.yaml"},
		{[]string{"--config", "with space.yaml"}, "with space.yaml"},
		{[]string{"-config=a", "--config=b"}, "b"},
		{[]string{"-config", "actual.yaml", "-password", "--config=other.yaml"}, "actual.yaml"},
		{[]string{"positional", "--config=ignored"}, "config.yaml"},
		{[]string{"--tui", "--standalone", "--password=secret", "--config=actual.yaml"}, "actual.yaml"},
		{[]string{"--no-browser=false", "--", "--config=ignored"}, "config.yaml"},
		{[]string{"--config", "--leading-hyphen.yaml"}, "--leading-hyphen.yaml"},
		{[]string{"-config=a", "--", "-config=b"}, "a"},
	} {
		got, err := cpaConfigPath(tc.args)
		if err != nil || got != tc.want {
			t.Fatalf("%v: %q %v", tc.args, got, err)
		}
	}
	for _, args := range [][]string{{"-config"}, {"--config="}, {"--unknown"}, {"--unknown=config"}, {"--config", ""}, {"--tui=invalid"}, {"--home-jwt", "private-secret"}} {
		if _, err := cpaConfigPath(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestEndpointFromConfig(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"server: {host: '', port: 8317, tls: {enable: false}}", "http://127.0.0.1:8317"},
		{"server: {host: '0.0.0.0', port: 1234}", "http://127.0.0.1:1234"},
		{"server: {host: '::', port: 443, tls: {enable: true}}", "https://[::1]:443"},
		{"server: {host: '2001:db8::1', port: 65535}", "http://[2001:db8::1]:65535"},
		{"server: {host: 'localhost', port: 1}\nunrelated: {secret: ignored}", "http://localhost:1"},
		{"server: {host: 'CPA-host.example.', port: 8317}", "http://CPA-host.example.:8317"},
	} {
		got, err := endpointFromConfig([]byte(tc.yaml))
		if err != nil || got != tc.want {
			t.Fatalf("%s: %q %v", tc.yaml, got, err)
		}
	}
	for _, raw := range []string{"", "server: {}", "port: 8317", "server: {port: 0}", "server: {port: -1}", "server: {port: 65536}", "server: {port: private-secret}", "server: [private-secret", "server: {port: 8317, tls: {enable: private-secret}}"} {
		_, err := endpointFromConfig([]byte(raw))
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("invalid config: %v", err)
		}
	}
}

func TestEndpointRejectsInvalidHosts(t *testing.T) {
	for _, host := range []string{
		"private-secret/path", "private-secret?query", "private-secret#fragment", "private-secret@localhost",
		"private-secret host", "private-secret\t", "[::1]", "[::1", "::1]", "localhost:8317",
		"private-secret%2flocalhost", "private-secret\\host", "-private-secret", "private-secret-", ".private-secret", "private-secret..example",
		strings.Repeat("x", 64) + ".private-secret", strings.Repeat("label.", 51) + "private-secret",
	} {
		// JSON strings are also valid YAML scalars and preserve control characters.
		data, err := json.Marshal(map[string]any{"server": map[string]any{"host": host, "port": 8317}})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint, err := endpointFromConfig(data); err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("host %q accepted or leaked: %q %v", host, endpoint, err)
		}
	}
}

func clearCPAStoreEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HOME_JWT", "PGSTORE_DSN", "PGSTORE_LOCAL_PATH", "WRITABLE_PATH", "GITSTORE_GIT_URL", "OBJECTSTORE_ENDPOINT"} {
		t.Setenv(key, "")
		t.Setenv(strings.ToLower(key), "")
	}
}

func TestCPAEndpointStartupPath(t *testing.T) {
	clearCPAStoreEnv(t)
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	path := filepath.Join(t.TempDir(), "startup.yaml")
	if err := os.WriteFile(path, []byte("server: {port: 4321, tls: {enable: true}}"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"cpa", "--config=" + path}
	got, err := cpaEndpoint()
	if err != nil || got != "https://127.0.0.1:4321" {
		t.Fatalf("startup: %q %v", got, err)
	}
	t.Setenv("PGSTORE_DSN", " \t ")
	t.Setenv("pgstore_dsn", " \t ")
	t.Setenv("PGSTORE_LOCAL_PATH", "private-secret")
	t.Setenv("WRITABLE_PATH", "private-secret")
	if got, err := cpaEndpoint(); err != nil || got != "https://127.0.0.1:4321" {
		t.Fatalf("blank DSN should use startup config: %q %v", got, err)
	}
	os.Args = []string{"cpa", "--config=" + path + "private-secret"}
	if _, err := cpaEndpoint(); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatalf("unreadable: %v", err)
	}
}

func TestCPAEndpointPostgresMirror(t *testing.T) {
	root := t.TempDir()
	custom, writable := filepath.Join(root, "custom"), filepath.Join(root, "writable")
	for _, tc := range []struct {
		name string
		env  map[string]string
		base string
	}{
		{"default", nil, "."},
		{"custom-upper", map[string]string{"PGSTORE_LOCAL_PATH": custom}, custom},
		{"custom-lower", map[string]string{"pgstore_local_path": custom}, custom},
		{"writable-upper", map[string]string{"WRITABLE_PATH": writable}, writable},
		{"writable-lower", map[string]string{"writable_path": writable}, writable},
		{"custom-before-writable", map[string]string{"PGSTORE_LOCAL_PATH": custom, "WRITABLE_PATH": writable}, custom},
		{"trimmed-relative", map[string]string{"PGSTORE_LOCAL_PATH": " \t custom-relative \t "}, "custom-relative"},
		{"blank-custom", map[string]string{"PGSTORE_LOCAL_PATH": " \t ", "WRITABLE_PATH": writable}, writable},
		{"postgres-before-other-stores", map[string]string{"GITSTORE_GIT_URL": "private-secret", "OBJECTSTORE_ENDPOINT": "private-secret"}, "."},
	} {
		for _, dsnKey := range []string{"PGSTORE_DSN", "pgstore_dsn"} {
			t.Run(tc.name+"/"+dsnKey, func(t *testing.T) {
				clearCPAStoreEnv(t)
				t.Chdir(t.TempDir())
				t.Setenv(dsnKey, " \t postgres://private-secret \t ")
				for key, value := range tc.env {
					t.Setenv(key, value)
				}
				path := filepath.Join(tc.base, "pgstore", "config", "config.yaml")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("server: {host: '::', port: 4321, tls: {enable: true}}"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile("config.yaml", []byte("server: {port: 9999}"), 0600); err != nil {
					t.Fatal(err)
				}
				old := os.Args
				t.Cleanup(func() { os.Args = old })
				for _, args := range [][]string{nil, {"--config=config.yaml"}, {"--config=missing-private-secret.yaml"}} {
					os.Args = append([]string{"cpa"}, args...)
					if got, err := cpaEndpoint(); err != nil || got != "https://[::1]:4321" {
						t.Fatalf("mirror: %q %v", got, err)
					}
				}
			})
		}
	}
}

func TestCPAEndpointPostgresDoesNotFallback(t *testing.T) {
	for _, raw := range []string{"missing", "server: {port: private-secret}", "server: {port: 0}", "server: [private-secret"} {
		t.Run(raw, func(t *testing.T) {
			clearCPAStoreEnv(t)
			t.Chdir(t.TempDir())
			t.Setenv("PGSTORE_DSN", "postgres://private-secret")
			t.Setenv("PGSTORE_LOCAL_PATH", "private-secret")
			t.Setenv("WRITABLE_PATH", "writable")
			for _, path := range []string{"config.yaml", "flag.yaml", filepath.Join("writable", "pgstore", "config", "config.yaml")} {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("server: {port: 9999}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if raw != "missing" {
				path := filepath.Join("private-secret", "pgstore", "config", "config.yaml")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			old := os.Args
			t.Cleanup(func() { os.Args = old })
			os.Args = []string{"cpa", "--config=flag.yaml"}
			if got, err := cpaEndpoint(); err == nil || got != "" || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("fallback or leaked secret: %q %v", got, err)
			}
		})
	}
}

func TestCPAEndpointPostgresValidatesFlags(t *testing.T) {
	clearCPAStoreEnv(t)
	t.Chdir(t.TempDir())
	t.Setenv("PGSTORE_DSN", "private-secret")
	path := filepath.Join("pgstore", "config", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("server: {port: 4321}"), 0600); err != nil {
		t.Fatal(err)
	}
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	for _, args := range [][]string{{"--config="}, {"--config"}, {"--unknown=private-secret"}, {"--tui=private-secret"}, {"--home-jwt=private-secret"}} {
		os.Args = append([]string{"cpa"}, args...)
		if got, err := cpaEndpoint(); err == nil || got != "" || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("invalid flags accepted or leaked: %q %v", got, err)
		}
	}
}

func TestCPAEnvCasePrecedence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows environment names are case-insensitive")
	}
	for _, key := range []string{"PGSTORE_DSN", "PGSTORE_LOCAL_PATH", "WRITABLE_PATH"} {
		t.Setenv(key, " upper ")
		t.Setenv(strings.ToLower(key), " lower ")
		if got := cpaEnv(key); got != "upper" {
			t.Fatalf("%s: %q", key, got)
		}
		t.Setenv(key, " \t ")
		if got := cpaEnv(key); got != "lower" {
			t.Fatalf("%s blank uppercase: %q", key, got)
		}
	}
}
