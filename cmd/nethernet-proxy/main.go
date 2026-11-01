// Command nethernet-proxy announces remote NetherNet Bedrock servers as LAN worlds and, when a
// console joins one of them, sends a Transfer packet that makes the console reconnect to the
// real server like to any remote server. The console then authenticates itself against the
// real server with its own Microsoft identity; this proxy never sees or forwards it.
//
// The only third-party code is pion's DTLS and SCTP; LAN discovery, signaling, SDP, ICE-lite,
// data channels and the Bedrock handshake are implemented in this repository.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"os"
	ossignal "os/signal"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// version is set at build time (-ldflags "-X main.version=..."). A binary built with
// "go install ...@v1.2.3" has no such flag; it falls back to the module version Go recorded.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
}

// dumpPackets logs the packet IDs of every session (debugging).
var dumpPackets bool

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON config (optional when -server is used)")
	var servers stringList
	flag.Var(&servers, "server", "server to announce, as host:port (repeatable; no config file needed)")
	check := flag.Bool("check", false, "ask the configured servers once, print the result and exit")
	verbose := flag.Bool("v", false, "debug logging")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.BoolVar(&dumpPackets, "dump", false, "log the ID and size of every Bedrock packet (debugging)")
	flag.Parse()
	if *showVersion {
		fmt.Println("NetherNetProxy", version)
		return
	}
	explicit := false
	flag.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	cfg, err := resolveConfig(*configPath, explicit, servers)
	if err != nil {
		log.Error("configuration", "error", err)
		os.Exit(1)
	}
	if *check {
		os.Exit(checkServers(cfg, os.Stdout))
	}

	ctx, stop := ossignal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := net.ListenPacket("udp4", cfg.Bind)
	if err != nil {
		log.Error("listen for LAN discovery", "error", err)
		os.Exit(1)
	}
	m := &mux{conn: conn, log: log, ctx: ctx, peers: map[uint64]peerEntry{}, worlds: map[uint64]*world{},
		sem: make(chan struct{}, maxNegotiations)}
	go m.pruneLoop()

	for _, wc := range cfg.Worlds {
		w := newWorld(m, wc)
		m.worlds[w.id] = w
		go w.refreshLoop(ctx)
	}
	log.Info("announcing worlds on LAN", "version", version, "bind", cfg.Bind, "worlds", len(cfg.Worlds))
	go m.run()

	<-ctx.Done()
	_ = conn.Close()
}

// mux owns the single UDP discovery socket and routes packets to the worlds.
type mux struct {
	conn net.PacketConn
	log  *slog.Logger
	ctx  context.Context

	mu     sync.RWMutex
	peers  map[uint64]peerEntry // client network ID -> last address
	worlds map[uint64]*world

	// sem bounds simultaneous connection setups; every setup allocates an ICE agent.
	sem chan struct{}
}

const (
	maxNegotiations = 16
	peerTTL         = 15 * time.Minute
)

type peerEntry struct {
	addr net.Addr
	seen time.Time
}

// pruneLoop forgets clients that have not been heard from for a while.
func (m *mux) pruneLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			for id, p := range m.peers {
				if time.Since(p.seen) > peerTTL {
					delete(m.peers, id)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *mux) run() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			if m.ctx.Err() == nil {
				m.log.Error("read discovery", "error", err)
			}
			return
		}
		pk, err := openPacket(buf[:n])
		if err != nil {
			continue
		}
		m.mu.RLock()
		_, ours := m.worlds[pk.sender]
		m.mu.RUnlock()
		if ours {
			continue
		}
		m.mu.Lock()
		m.peers[pk.sender] = peerEntry{addr: addr, seen: time.Now()}
		m.mu.Unlock()

		switch pk.kind {
		case pktRequest:
			m.mu.RLock()
			for _, w := range m.worlds {
				if card := w.currentCard(); card != nil {
					_, _ = m.conn.WriteTo(buildResponse(w.id, card), addr)
				}
			}
			m.mu.RUnlock()
		case pktMessage:
			m.mu.RLock()
			w := m.worlds[pk.recipient]
			m.mu.RUnlock()
			if w == nil || pk.data == "" || pk.data == "Ping" {
				continue
			}
			sig, err := parseSignal(pk.data)
			if err != nil {
				m.log.Debug("bad signal", "error", err)
				continue
			}
			w.onSignal(pk.sender, sig)
		}
	}
}

type negKey struct{ peer, conn uint64 }

// world is one announced server.
type world struct {
	m     *mux
	cfg   WorldConfig
	id    uint64
	log   *slog.Logger
	nonce string

	mu   sync.Mutex
	card []byte
	negs map[negKey]*negotiation
}

func newWorld(m *mux, cfg WorldConfig) *world {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s|%s|%d", cfg.Name, cfg.Host, cfg.Port)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return &world{
		m: m, cfg: cfg, id: h.Sum64() | 1<<62, nonce: hex.EncodeToString(nonce),
		log:  m.log.With("world", cfg.Name),
		negs: map[negKey]*negotiation{},
	}
}

func (w *world) currentCard() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.card
}

func (w *world) refreshLoop(ctx context.Context) {
	for {
		w.refresh()
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func (w *world) refresh() {
	url := infoURL(w.cfg.Host, w.cfg.Port)
	info, err := fetchInfo(url)
	if err != nil {
		w.log.Warn("server info unavailable", "url", url, "error", err)
		return
	}
	card := serverCard{
		Name: info.Name, Version: info.Version, Level: info.Level, Nonce: w.nonce,
		Protocol: info.Protocol, Players: info.Players, Max: info.MaxPlayers, GameType: info.GameType,
	}.marshal()
	w.mu.Lock()
	first := w.card == nil
	w.card = card
	w.mu.Unlock()
	if first {
		w.log.Info("world announced", "level", info.Level, "version", info.Version, "id", w.id)
	}
}

// sendSignal delivers a signaling message to a client over LAN discovery.
func (w *world) sendSignal(peer uint64, s signal) {
	w.m.mu.RLock()
	entry, ok := w.m.peers[peer]
	w.m.mu.RUnlock()
	addr := entry.addr
	if !ok {
		w.log.Debug("no address for peer", "peer", peer)
		return
	}
	text := s.String()
	if len(text) > 1140 {
		w.log.Warn("LAN message exceeds 1140 bytes; clients may drop it", "bytes", len(text), "type", s.typ)
	}
	w.log.Debug("signal out", "type", s.typ, "bytes", len(text))
	_, _ = w.m.conn.WriteTo(buildMessage(w.id, peer, text), addr)
}

// onSignal handles a signaling message addressed to this world.
func (w *world) onSignal(peer uint64, s signal) {
	key := negKey{peer, s.connID}
	w.log.Debug("signal in", "type", s.typ, "bytes", len(s.data))
	switch s.typ {
	case sigOffer:
		select {
		case w.m.sem <- struct{}{}:
		default:
			w.log.Warn("too many simultaneous connection setups, offer dropped", "peer", peer)
			w.sendSignal(peer, signal{typ: sigError, connID: s.connID, data: strconv.Itoa(errCodeCreatePeerConnection)})
			return
		}
		w.mu.Lock()
		if _, dup := w.negs[key]; dup {
			w.mu.Unlock()
			<-w.m.sem
			return
		}
		n := newNegotiation()
		w.negs[key] = n
		w.mu.Unlock()
		go func() {
			defer func() { <-w.m.sem }()
			w.negotiate(s, peer, n, w.transfer)
			w.mu.Lock()
			delete(w.negs, key)
			w.mu.Unlock()
		}()
	case sigCandidate:
		w.mu.Lock()
		n := w.negs[key]
		w.mu.Unlock()
		if n != nil {
			select {
			case n.cands <- s.data:
			default:
			}
		}
	case sigError:
		w.mu.Lock()
		n := w.negs[key]
		w.mu.Unlock()
		if n != nil {
			n.abortOnce.Do(func() { close(n.abort) })
		}
	}
}

func (w *world) transfer(conn *nnConn) {
	target := fmt.Sprintf("%s:%d", w.cfg.Host, w.cfg.Port)
	w.log.Info("console joined, transferring", "remote", conn.RemoteAddr(), "target", target)
	if err := serveTransfer(conn, w.cfg.Host, w.cfg.Port, w.log, dumpPackets); err != nil {
		w.log.Warn("session ended", "error", err)
		return
	}
	w.log.Info("console transferred", "target", target)
}
