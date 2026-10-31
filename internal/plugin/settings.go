package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func validateSettings(c config) error {
	if strings.ContainsAny(c.Key, "\r\n") || !validURL(c.URL) {
		return errors.New("Invalid settings")
	}
	return nil
}

func loadSettings(path string) (config, error) {
	c := config{Excludes: []string{}}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		// Windows also reports a missing path when an ancestor is a regular file.
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			info, statErr := os.Stat(dir)
			if statErr == nil && info.IsDir() {
				return c, nil
			}
			if !os.IsNotExist(statErr) || filepath.Dir(dir) == dir {
				return c, errors.New("Unable to read settings")
			}
		}
	}
	if err != nil {
		return c, errors.New("Unable to read settings")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSettingsSize+1))
	if err != nil {
		return c, errors.New("Unable to read settings")
	}
	if len(data) > maxSettingsSize || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) || json.Unmarshal(data, &c) != nil || validateSettings(c) != nil {
		return config{Excludes: []string{}}, errors.New("Invalid settings")
	}
	if c.Excludes == nil {
		c.Excludes = []string{}
	}
	return c, nil
}

func writeSettings(path string, c config) error {
	if err := validateSettings(c); err != nil {
		return err
	}
	if c.Excludes == nil {
		c.Excludes = []string{}
	}
	data, err := json.Marshal(c)
	if err != nil || len(data) > maxSettingsSize {
		return errors.New("Invalid settings")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("Unable to save settings")
	}
	f, err := os.CreateTemp(dir, ".settings-*")
	if err != nil {
		return errors.New("Unable to save settings")
	}
	defer os.Remove(f.Name())
	// CreateTemp creates a private file; chmod also enforces the mode before replacement.
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("Unable to save settings")
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.New("Unable to save settings")
	}
	return nil
}

func cpaConfigPath(args []string) (string, error) {
	fs := flag.NewFlagSet("CPA", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "config.yaml", "")
	homeJWT := fs.String("home-jwt", "", "")
	// shortcut: CPA RPC omits its config path; update flag arities when upstream CLI changes.
	for _, name := range []string{
		"password", "management-base-url", "vertex-import", "vertex-import-prefix", "siwc-bind",
		"oauth-callback-port", "discover-timeout", "discover-service-type", "discover-include", "discover-exclude",
	} {
		fs.String(name, "", "")
	}
	for _, name := range []string{
		"codex-login", "codex-device-login", "claude-login", "no-browser", "antigravity-login",
		"kimi-login", "kimi-ai-login", "xai-login", "devin-login", "meta-login",
		"discover", "discover-json", "home-disable-cluster-discovery", "tui", "standalone", "local-model",
	} {
		fs.Bool(name, false, "")
	}
	if err := fs.Parse(args); err != nil || *path == "" || strings.TrimSpace(*homeJWT) != "" {
		return "", errors.New("Invalid CPA config path")
	}
	return *path, nil
}

func cpaEnv(key string) string {
	for _, name := range []string{key, strings.ToLower(key)} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func cpaEndpoint() (string, error) {
	if cpaEnv("HOME_JWT") != "" {
		return "", errors.New("CPA listener discovery does not support Home configuration")
	}
	path, err := cpaConfigPath(os.Args[1:])
	if err != nil {
		return "", err
	}
	// CPA selects Home before PostgreSQL, then object/git stores; PostgreSQL ignores -config.
	if cpaEnv("PGSTORE_DSN") != "" {
		base := cpaEnv("PGSTORE_LOCAL_PATH")
		if base == "" {
			base = cpaEnv("WRITABLE_PATH")
		}
		if base == "" {
			base, err = os.Getwd()
			if err != nil {
				return "", errors.New("Unable to resolve CPA PostgreSQL config directory")
			}
		}
		path = filepath.Join(base, "pgstore", "config", "config.yaml")
	} else if cpaEnv("GITSTORE_GIT_URL") != "" || cpaEnv("OBJECTSTORE_ENDPOINT") != "" {
		return "", errors.New("CPA listener discovery does not support git or object-store configuration")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("Unable to read CPA config; the selected local config file is required")
	}
	return endpointFromConfig(data)
}

func endpointFromConfig(data []byte) (string, error) {
	var c struct {
		Server struct {
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
			TLS  struct {
				Enable bool `yaml:"enable"`
			} `yaml:"tls"`
		} `yaml:"server"`
	}
	if yaml.Unmarshal(data, &c) != nil || c.Server.Port < 1 || c.Server.Port > 65535 {
		return "", errors.New("Invalid CPA config; server.port must be 1..65535")
	}
	host := c.Server.Host
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	if net.ParseIP(host) == nil {
		name := strings.TrimSuffix(host, ".")
		if len(name) > 253 {
			return "", errors.New("Invalid CPA config; invalid server.host")
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("Invalid CPA config; invalid server.host")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", errors.New("Invalid CPA config; invalid server.host")
				}
			}
		}
	}
	scheme := "http"
	if c.Server.TLS.Enable {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(c.Server.Port)), nil
}
