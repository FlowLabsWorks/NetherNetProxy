package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the JSON configuration file. Everything except the servers is optional.
type Config struct {
	Bind   string        `json:"bind"`   // UDP address for LAN discovery, default ":7551"
	Host   string        `json:"host"`   // default host of the servers below
	Worlds []WorldConfig `json:"worlds"` // one entry per announced server
}

// WorldConfig describes one real server.
type WorldConfig struct {
	Name string `json:"name,omitempty"` // only for logs; default "host:port"
	Host string `json:"host,omitempty"` // overrides Config.Host
	Port uint16 `json:"port"`           // server-port of the server (TCP signaling, also the transfer target)
}

// serverInfo is the answer of GET /v1/join on a NetherNet Bedrock server.
type serverInfo struct {
	Name       string `json:"name"`
	Protocol   int32  `json:"protocol"`
	Version    string `json:"version"`
	Level      string `json:"level"`
	Players    int32  `json:"players"`
	MaxPlayers int32  `json:"maxPlayers"`
	GameType   int32  `json:"gameType"`
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parseServerArg parses "host:port" (IPv6 as "[::1]:19132").
func parseServerArg(arg string) (WorldConfig, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(arg))
	if err != nil || host == "" {
		return WorldConfig{}, fmt.Errorf("%q: expected host:port", arg)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return WorldConfig{}, fmt.Errorf("%q: invalid port", arg)
	}
	return WorldConfig{Host: host, Port: uint16(port)}, nil
}

// normalize fills defaults and validates the configuration.
func (c *Config) normalize() error {
	if c.Bind == "" {
		c.Bind = ":7551"
	}
	if len(c.Worlds) == 0 {
		return errors.New("no servers configured")
	}
	seen := map[string]bool{}
	for i := range c.Worlds {
		w := &c.Worlds[i]
		if w.Host == "" {
			w.Host = c.Host
		}
		if w.Host == "" {
			return fmt.Errorf("server #%d has no host (set \"host\" at the top level or per server)", i+1)
		}
		if w.Port == 0 {
			return fmt.Errorf("server #%d (%s) has no port", i+1, w.Host)
		}
		addr := net.JoinHostPort(w.Host, strconv.Itoa(int(w.Port)))
		if w.Name == "" {
			w.Name = addr
		}
		if seen[addr] {
			return fmt.Errorf("server %s is configured twice", addr)
		}
		seen[addr] = true
	}
	return nil
}

// resolveConfig reads the config file (optional when servers are given on the command line)
// and adds the servers passed as "host:port".
func resolveConfig(path string, explicit bool, servers []string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("%s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist) && !explicit && len(servers) > 0:
		// Command-line servers only.
	case errors.Is(err, os.ErrNotExist) && !explicit:
		return cfg, fmt.Errorf("no configuration: pass -server host:port or create %s (see config.example.json)", path)
	default:
		return cfg, err
	}
	for _, s := range servers {
		w, err := parseServerArg(s)
		if err != nil {
			return cfg, err
		}
		cfg.Worlds = append(cfg.Worlds, w)
	}
	return cfg, cfg.normalize()
}

const infoTimeout = 8 * time.Second

func infoURL(host string, port uint16) string {
	return "http://" + net.JoinHostPort(host, strconv.Itoa(int(port))) + "/v1/join"
}

// fetchInfo asks a NetherNet server for its public info (name, version, level, players).
func fetchInfo(url string) (serverInfo, error) {
	client := http.Client{Timeout: infoTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return serverInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serverInfo{}, fmt.Errorf("HTTP %d (is transport=nethernet set on the server?)", resp.StatusCode)
	}
	var info serverInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil {
		return serverInfo{}, fmt.Errorf("unreadable answer: %w", err)
	}
	return info, nil
}

// checkServers queries every configured server once and prints one line each. It returns
// the process exit code: 0 if all servers answered, 1 otherwise.
func checkServers(cfg Config, out io.Writer) int {
	code := 0
	for _, w := range cfg.Worlds {
		info, err := fetchInfo(infoURL(w.Host, w.Port))
		addr := net.JoinHostPort(w.Host, strconv.Itoa(int(w.Port)))
		if err != nil {
			fmt.Fprintf(out, "FAIL  %-30s %v\n", addr, err)
			code = 1
			continue
		}
		fmt.Fprintf(out, "OK    %-30s level=%q version=%s protocol=%d players=%d/%d\n",
			addr, info.Level, info.Version, info.Protocol, info.Players, info.MaxPlayers)
	}
	return code
}
