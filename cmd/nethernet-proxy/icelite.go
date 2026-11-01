package main

// ICE-lite (RFC 8445 section 3): the console, being the offerer, runs the full ICE agent and
// sends the connectivity checks. This side only listens on one UDP socket, answers the
// Binding requests, remembers where they came from and passes DTLS packets on. Host candidates
// only; no gathering, no TURN, no mDNS.

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/transport/v5/deadline"
)

type iceLite struct {
	log   *slog.Logger
	udp   *net.UDPConn
	ufrag string
	pwd   string

	dtlsIn chan []byte
	up     chan struct{} // closed on the first valid connectivity check
	upOnce sync.Once

	closed    chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	selected *net.UDPAddr
	peers    map[string]bool // addresses that sent a valid check
}

const iceAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = iceAlphabet[int(b[i])%len(iceAlphabet)]
	}
	return string(b)
}

func newICELite(log *slog.Logger) (*iceLite, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	return &iceLite{
		log: log, udp: udp, ufrag: randomString(8), pwd: randomString(24),
		dtlsIn: make(chan []byte, 64), up: make(chan struct{}), closed: make(chan struct{}),
		peers: map[string]bool{},
	}, nil
}

func (l *iceLite) port() int { return l.udp.LocalAddr().(*net.UDPAddr).Port }

func (l *iceLite) selectedAddr() *net.UDPAddr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.selected
}

func (l *iceLite) close() {
	l.closeOnce.Do(func() {
		close(l.closed)
		_ = l.udp.Close()
	})
}

// run reads the socket until it is closed: STUN goes to handleSTUN, DTLS to the DTLS conn.
func (l *iceLite) run() {
	buf := make([]byte, 2048)
	for {
		n, from, err := l.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		switch b := buf[:n]; {
		case b[0] <= 3: // STUN
			l.handleSTUN(append([]byte(nil), b...), from)
		case b[0] >= 20 && b[0] <= 63: // DTLS
			l.mu.Lock()
			known := l.peers[from.String()]
			l.mu.Unlock()
			if known {
				select {
				case l.dtlsIn <- append([]byte(nil), b...):
				default: // DTLS retransmits
				}
			}
		}
	}
}

func (l *iceLite) handleSTUN(b []byte, from *net.UDPAddr) {
	m, err := parseSTUN(b)
	if err != nil || m.typ != stunBindingRequest {
		return
	}
	user := m.attr(attrUsername)
	if user == nil || !strings.HasPrefix(string(user.val), l.ufrag+":") {
		return
	}
	if !m.verifyIntegrity([]byte(l.pwd)) || !m.verifyFingerprint() {
		l.log.Debug("STUN check rejected", "from", from)
		return
	}
	_, _ = l.udp.WriteToUDP(buildBindingSuccess(m.tx, from, []byte(l.pwd)), from)

	l.mu.Lock()
	l.peers[from.String()] = true
	if l.selected == nil || m.attr(attrUseCandidate) != nil {
		l.selected = from
	}
	l.mu.Unlock()
	l.upOnce.Do(func() { close(l.up) })
}

// localCandidates lists host candidates, one per usable IPv4 address, as SDP attribute lines.
// The error is the reason the host's interfaces could not be listed (for example a sandbox that
// blocks netlink sockets); an empty list without an error means there is no usable address.
func localCandidates(port int, ufrag string) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || !ifaceFilter(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses of %s: %w", ifc.Name, err)
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || ip.IsLinkLocalUnicast() {
				continue
			}
			i := len(out)
			priority := (126 << 24) | ((65535 - i) << 8) | 255
			out = append(out, fmt.Sprintf(
				"a=candidate:%d 1 udp %d %s %d typ host generation 0 ufrag %s network-id %d network-cost 0",
				i+1, priority, ip, port, ufrag, i))
		}
	}
	return out, nil
}

// liteConn presents the ICE-lite socket as the net.PacketConn pion/dtls expects: it delivers
// the DTLS packets and sends to the selected address.
type liteConn struct {
	l  *iceLite
	rd *deadline.Deadline
}

func newLiteConn(l *iceLite) *liteConn { return &liteConn{l: l, rd: deadline.New()} }

func (c *liteConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-c.l.dtlsIn:
		return copy(p, b), c.l.selectedAddr(), nil
	case <-c.rd.Done():
		return 0, nil, c.rd.Err()
	case <-c.l.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *liteConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.l.closed:
		return 0, net.ErrClosed
	default:
	}
	to := c.l.selectedAddr()
	if to == nil {
		return 0, os.ErrInvalid
	}
	return c.l.udp.WriteToUDP(p, to)
}

func (c *liteConn) Close() error                       { c.l.close(); return nil }
func (c *liteConn) LocalAddr() net.Addr                { return c.l.udp.LocalAddr() }
func (c *liteConn) SetDeadline(t time.Time) error      { c.rd.Set(t); return nil }
func (c *liteConn) SetReadDeadline(t time.Time) error  { c.rd.Set(t); return nil }
func (c *liteConn) SetWriteDeadline(t time.Time) error { return nil }
