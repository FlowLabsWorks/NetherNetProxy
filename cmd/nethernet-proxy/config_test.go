package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseServerArg(t *testing.T) {
	good := map[string]WorldConfig{
		"minecraft.example.com:19132": {Host: "minecraft.example.com", Port: 19132},
		" 10.0.0.5:22448 ":            {Host: "10.0.0.5", Port: 22448},
		"[::1]:19132":                 {Host: "::1", Port: 19132},
	}
	for in, want := range good {
		got, err := parseServerArg(in)
		if err != nil || got != want {
			t.Errorf("parseServerArg(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "example.com", "example.com:", ":19132", "example.com:0", "example.com:70000", "example.com:abc"} {
		if _, err := parseServerArg(in); err == nil {
			t.Errorf("parseServerArg(%q) accepted invalid input", in)
		}
	}
}

func TestNormalize(t *testing.T) {
	cfg := Config{Host: "a.example", Worlds: []WorldConfig{{Port: 1}, {Name: "x", Host: "b.example", Port: 2}}}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.Bind != ":7551" || cfg.Worlds[0].Host != "a.example" || cfg.Worlds[0].Name != "a.example:1" || cfg.Worlds[1].Name != "x" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}

	bad := map[string]Config{
		"no servers": {},
		"no host":    {Worlds: []WorldConfig{{Port: 1}}},
		"no port":    {Host: "a", Worlds: []WorldConfig{{}}},
		"duplicate":  {Host: "a", Worlds: []WorldConfig{{Port: 1}, {Name: "other", Port: 1}}},
	}
	for name, c := range bad {
		if err := c.normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolveConfig(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte(`{"host":"h.example","worlds":[{"port":1},{"name":"two","port":2}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// File plus command-line servers are combined.
	cfg, err := resolveConfig(file, true, []string{"o.example:3"})
	if err != nil || len(cfg.Worlds) != 3 || cfg.Worlds[2].Host != "o.example" {
		t.Fatalf("combined config: %+v, %v", cfg, err)
	}

	missing := filepath.Join(dir, "missing.json")
	// Missing default file is fine when servers are given on the command line.
	if cfg, err = resolveConfig(missing, false, []string{"o.example:3"}); err != nil || len(cfg.Worlds) != 1 {
		t.Fatalf("flags only: %+v, %v", cfg, err)
	}
	// Missing default file without servers is an actionable error.
	if _, err = resolveConfig(missing, false, nil); err == nil || !strings.Contains(err.Error(), "-server") {
		t.Fatalf("expected a hint about -server, got %v", err)
	}
	// An explicitly requested file that does not exist is always an error.
	if _, err = resolveConfig(missing, true, []string{"o.example:3"}); err == nil {
		t.Fatal("explicit missing config accepted")
	}
	// Broken JSON names the file.
	broken := filepath.Join(dir, "broken.json")
	_ = os.WriteFile(broken, []byte(`{`), 0o600)
	if _, err = resolveConfig(broken, true, nil); err == nil || !strings.Contains(err.Error(), "broken.json") {
		t.Fatalf("expected the file name in the error, got %v", err)
	}
}

func TestFetchInfoAndCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/join", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"Test","protocol":2225,"version":"1.26.60","level":"SURVIVAL","players":1,"maxPlayers":2,"gameType":0}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	info, err := fetchInfo(srv.URL + "/v1/join")
	if err != nil || info.Level != "SURVIVAL" || info.Protocol != 2225 || info.MaxPlayers != 2 {
		t.Fatalf("fetchInfo = %+v, %v", info, err)
	}
	if _, err := fetchInfo(srv.URL + "/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected an HTTP 404 error, got %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not json")) }))
	defer bad.Close()
	if _, err := fetchInfo(bad.URL); err == nil {
		t.Fatal("accepted a non-JSON answer")
	}

	// checkServers: one reachable and one dead server.
	host, port := splitHostPort(t, srv.Listener.Addr().String())
	cfg := Config{Worlds: []WorldConfig{{Host: host, Port: port}, {Host: "127.0.0.1", Port: 1}}}
	var out bytes.Buffer
	if code := checkServers(cfg, &out); code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "OK") || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("unexpected check output:\n%s", out.String())
	}
	cfg.Worlds = cfg.Worlds[:1]
	out.Reset()
	if code := checkServers(cfg, &out); code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, out.String())
	}
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	w, err := parseServerArg(addr)
	if err != nil {
		t.Fatal(err)
	}
	return w.Host, w.Port
}
