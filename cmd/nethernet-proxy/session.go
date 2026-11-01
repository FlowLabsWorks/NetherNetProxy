package main

// Answering a WebRTC offer from a console and turning it into a message connection:
//
//	SDP (text) -> ICE-lite (icelite.go) -> DTLS -> SCTP -> data channels (DCEP) -> segments
//
// DTLS and SCTP come from pion; everything else is written here.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// -- SDP (text) --------------------------------------------------------------------------

const (
	maxSegment    = 262143 // 'a=max-message-size' of vanilla (256 KiB) minus the counter byte
	maxPending    = 4 << 20
	sctpMTU       = 1191
	labelReliable = "ReliableDataChannel"
	labelUnrel    = "UnreliableDataChannel"
)

type fingerprint struct{ algorithm, value string }

// remoteOffer holds what is needed from the client's SDP offer.
type remoteOffer struct {
	fingerprints []fingerprint
	server       bool // the client is the DTLS server ("passive")
	maxMessage   uint32
}

func parseOffer(text string) (*remoteOffer, error) {
	o := &remoteOffer{maxMessage: maxSegment + 1}
	media := 0
	var haveUfrag, havePwd, haveSetup bool
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "m="):
			media++
		case strings.HasPrefix(line, "a="):
			key, value, _ := strings.Cut(line[2:], ":")
			switch key {
			case "ice-ufrag":
				haveUfrag = true
			case "ice-pwd":
				havePwd = true
			case "fingerprint":
				f := strings.Fields(value)
				if len(f) != 2 {
					return nil, errors.New("bad fingerprint")
				}
				o.fingerprints = append(o.fingerprints, fingerprint{strings.ToLower(f[0]), f[1]})
			case "setup":
				haveSetup = true
				o.server = value == "passive"
			case "max-message-size":
				if n, err := strconv.ParseUint(value, 10, 32); err == nil && n > 1 {
					o.maxMessage = uint32(n)
				}
			}
		}
	}
	switch {
	case media != 1:
		return nil, fmt.Errorf("expected 1 media section, got %d", media)
	case !haveUfrag || !havePwd:
		return nil, errors.New("missing ICE credentials")
	case len(o.fingerprints) == 0:
		return nil, errors.New("missing fingerprint")
	case !haveSetup:
		return nil, errors.New("missing setup")
	}
	return o, nil
}

// buildAnswer writes the SDP answer of an ICE-lite host. active is the local DTLS role:
// true = DTLS client, false = DTLS server.
func buildAnswer(ufrag, pwd, fp string, candidates []string, active bool) string {
	setup := "passive"
	if active {
		setup = "active"
	}
	lines := []string{
		"v=0",
		fmt.Sprintf("o=- %d 2 IN IP4 127.0.0.1", randUint64()),
		"s=-",
		"t=0 0",
		"a=ice-lite",
		"a=group:BUNDLE 0",
		"a=extmap-allow-mixed",
		"a=msid-semantic: WMS",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
		"c=IN IP4 0.0.0.0",
	}
	lines = append(lines, candidates...)
	lines = append(lines,
		"a=end-of-candidates",
		"a=ice-ufrag:"+ufrag,
		"a=ice-pwd:"+pwd,
		"a=ice-options:trickle",
		"a=fingerprint:sha-256 "+fp,
		"a=setup:"+setup,
		"a=mid:0",
		"a=sctp-port:5000",
		"a=max-message-size:"+strconv.Itoa(maxSegment+1),
	)
	return strings.Join(lines, "\r\n") + "\r\n"
}

func randUint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) >> 1
}

// -- certificates and fingerprints -------------------------------------------------------

func newCertificate() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tpl := x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "WebRTC"},
		Issuer:             pkix.Name{CommonName: "WebRTC"},
		NotBefore:          time.Now().AddDate(0, 0, -1),
		NotAfter:           time.Now().AddDate(0, 1, -1),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fingerprintOf("sha-256", der), nil
}

func fingerprintOf(algorithm string, der []byte) string {
	var sum []byte
	switch algorithm {
	case "sha-256":
		s := sha256.Sum256(der)
		sum = s[:]
	case "sha-384":
		s := sha512.Sum384(der)
		sum = s[:]
	case "sha-512":
		s := sha512.Sum512(der)
		sum = s[:]
	default:
		return ""
	}
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func verifyFingerprint(want []fingerprint) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("peer sent no certificate")
		}
		for _, f := range want {
			if got := fingerprintOf(f.algorithm, raw[0]); got != "" && strings.EqualFold(got, f.value) {
				return nil
			}
		}
		return errors.New("peer certificate does not match the offered fingerprint")
	}
}

// ifaceFilter keeps candidates away from container and loopback interfaces: their addresses
// are useless to a console on the LAN.
func ifaceFilter(name string) bool {
	for _, prefix := range []string{"lo", "docker", "veth", "br-", "virbr"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// pionLog gives pion its logger factory; some packages dereference it without a nil check.
var pionLog = logging.NewDefaultLoggerFactory()

// -- the connection ----------------------------------------------------------------------

// nnConn is an established NetherNet connection. Messages are whole Bedrock batches.
type nnConn struct {
	log    *slog.Logger
	remote string

	lite  *iceLite
	dtls  *dtls.Conn
	assoc *sctp.Association

	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once

	reliable   reliableChannel
	openedOnce sync.Once
	maxSeg     atomic.Int64
}

type reliableChannel struct {
	stream  atomic.Pointer[sctp.Stream]
	mu      sync.Mutex
	pending []byte
	left    int // promised remaining segments
	packets chan []byte
	write   sync.Mutex
}

func (c *nnConn) RemoteAddr() string { return c.remote }

// ReadPacket returns the next whole message received on the reliable channel.
func (c *nnConn) ReadPacket() ([]byte, error) {
	select {
	case <-c.ctx.Done():
		return nil, fmt.Errorf("connection closed: %w", context.Cause(c.ctx))
	case p := <-c.reliable.packets:
		return p, nil
	}
}

// Write sends b as one message, split into counted segments when it is large.
func (c *nnConn) Write(b []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed: %w", context.Cause(c.ctx))
	default:
	}
	stream := c.reliable.stream.Load()
	if stream == nil {
		return 0, errors.New("reliable channel not open")
	}
	size := int(c.maxSeg.Load())
	if size <= 0 {
		size = maxSegment
	}
	total := 1
	if len(b) > 0 {
		total = (len(b)-1)/size + 1
	}
	if total > 255 {
		return 0, fmt.Errorf("message of %d bytes needs %d segments", len(b), total)
	}
	c.reliable.write.Lock()
	defer c.reliable.write.Unlock()
	remaining := total - 1
	sent := 0
	for i := 0; i == 0 || i < len(b); i += size {
		end := min(len(b), i+size)
		if _, err := stream.WriteSCTP(append([]byte{byte(remaining)}, b[i:end]...), sctp.PayloadTypeWebRTCBinary); err != nil {
			return sent, err
		}
		sent += end - i
		remaining--
	}
	return sent, nil
}

func (c *nnConn) Close() error { return c.closeWith(errors.New("closed")) }

func (c *nnConn) closeWith(cause error) error {
	c.once.Do(func() {
		c.log.Debug("connection closing", "cause", cause)
		c.cancel(cause)
		if s := c.reliable.stream.Load(); s != nil {
			_ = s.Close()
		}
		if c.assoc != nil {
			_ = c.assoc.Close()
		}
		if c.dtls != nil {
			_ = c.dtls.Close()
		}
		c.lite.close()
	})
	return nil
}

// handle reassembles segments of the reliable channel into whole messages.
func (r *reliableChannel) handle(ctx context.Context, msg []byte) error {
	if len(msg) < 2 {
		return io.ErrUnexpectedEOF
	}
	r.mu.Lock()
	remaining := int(msg[0])
	if r.left > 0 && r.left-1 != remaining {
		r.mu.Unlock()
		return fmt.Errorf("invalid segment counter: expected %d, got %d", r.left-1, remaining)
	}
	if len(r.pending)+len(msg)-1 > maxPending {
		r.mu.Unlock()
		return errors.New("message too large")
	}
	r.left = remaining
	r.pending = append(r.pending, msg[1:]...)
	if r.left > 0 {
		r.mu.Unlock()
		return nil
	}
	data := r.pending
	r.pending = nil
	r.mu.Unlock()
	select {
	case r.packets <- data:
	case <-ctx.Done():
	}
	return nil
}

// negotiation is one in-flight offer.
type negotiation struct {
	cands     chan string // remote CANDIDATEADD payloads (not needed by an ICE-lite host)
	abort     chan struct{}
	abortOnce sync.Once
}

func newNegotiation() *negotiation {
	return &negotiation{cands: make(chan string, 32), abort: make(chan struct{})}
}

// negotiate answers an offer and, once the reliable channel is open, hands the connection to
// handle. It returns when handle has returned or the negotiation failed.
func (w *world) negotiate(offerSig signal, peer uint64, n *negotiation, handle func(*nnConn)) {
	log := w.log.With("peer", peer, "conn", offerSig.connID)
	fail := func(code int, err error) {
		log.Warn("negotiation failed", "error", err)
		w.sendSignal(peer, signal{typ: sigError, connID: offerSig.connID, data: strconv.Itoa(code)})
	}

	offer, err := parseOffer(offerSig.data)
	if err != nil {
		fail(errCodeSetRemoteDescription, err)
		return
	}
	cert, localFP, err := newCertificate()
	if err != nil {
		fail(errCodeCreateAnswer, err)
		return
	}
	lite, err := newICELite(log)
	if err != nil {
		fail(errCodeCreatePeerConnection, err)
		return
	}
	candidates, err := localCandidates(lite.port(), lite.ufrag)
	if err == nil && len(candidates) == 0 {
		err = errors.New("no usable local IPv4 address (loopback, docker and bridge interfaces are skipped)")
	}
	if err != nil {
		lite.close()
		fail(errCodeICE, err)
		return
	}

	conn := &nnConn{log: log, remote: fmt.Sprintf("%d", peer), lite: lite}
	conn.reliable.packets = make(chan []byte, 16)
	conn.ctx, conn.cancel = context.WithCancelCause(context.Background())
	conn.maxSeg.Store(int64(min(offer.maxMessage, maxSegment+1)) - 1)
	established := false
	defer func() {
		if !established {
			_ = conn.closeWith(errors.New("negotiation ended"))
		}
	}()
	go func() {
		select {
		case <-n.abort:
			_ = conn.closeWith(errors.New("aborted by client"))
		case <-conn.ctx.Done():
		}
	}()
	go func() { // remote candidates are not needed: the console sends the checks
		for {
			select {
			case <-conn.ctx.Done():
				return
			case <-n.cands:
			}
		}
	}()

	// Listen before the answer goes out: the checks can start right after it.
	go lite.run()
	// As the lite side we are the DTLS server, unless the console insists on being one.
	active := offer.server
	w.sendSignal(peer, signal{typ: sigAnswer, connID: offerSig.connID, data: buildAnswer(lite.ufrag, lite.pwd, localFP, candidates, active)})

	ctx, cancel := context.WithTimeout(conn.ctx, 15*time.Second)
	defer cancel()
	select {
	case <-lite.up:
	case <-ctx.Done():
		fail(errCodeICE, errors.New("no connectivity check received"))
		return
	}
	remote := lite.selectedAddr()
	conn.remote = remote.String()

	pc := newLiteConn(lite)
	opts := []dtls.Option{
		dtls.WithCertificates(cert),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AEAD_AES_256_GCM, dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithLoggerFactory(pionLog),
		dtls.WithVerifyPeerCertificate(verifyFingerprint(offer.fingerprints)),
	}
	if active {
		clientOpts := make([]dtls.ClientOption, len(opts))
		for i, o := range opts {
			clientOpts[i] = o
		}
		conn.dtls, err = dtls.ClientWithOptions(pc, remote, clientOpts...)
	} else {
		serverOpts := make([]dtls.ServerOption, 0, len(opts)+1)
		for _, o := range opts {
			serverOpts = append(serverOpts, o)
		}
		serverOpts = append(serverOpts, dtls.WithClientAuth(dtls.RequireAnyClientCert))
		conn.dtls, err = dtls.ServerWithOptions(pc, remote, serverOpts...)
	}
	if err != nil {
		fail(errCodeICE, fmt.Errorf("DTLS: %w", err))
		return
	}
	if err := conn.dtls.HandshakeContext(ctx); err != nil {
		fail(errCodeICE, fmt.Errorf("DTLS handshake: %w", err))
		return
	}

	conn.assoc, err = sctp.ClientContext(ctx,
		sctp.WithNetConn(conn.dtls),
		sctp.WithLoggerFactory(pionLog),
		sctp.WithMTU(sctpMTU),
		sctp.WithMaxMessageSize(offer.maxMessage),
	)
	if err != nil {
		fail(errCodeICE, fmt.Errorf("SCTP: %w", err))
		return
	}

	opened := make(chan struct{})
	go conn.acceptStreams(opened)
	select {
	case <-opened:
	case <-ctx.Done():
		fail(errCodeICE, errors.New("data channel did not open"))
		return
	}
	established = true
	handle(conn)
	_ = conn.closeWith(errors.New("finished"))
}

// -- data channels (RFC 8831 / 8832) ------------------------------------------------------

const (
	dcepOpen = 0x03
	dcepAck  = 0x02
)

// acceptStreams answers the data channels the client opens. Only the reliable one carries the
// game; the unreliable one is read and discarded.
func (c *nnConn) acceptStreams(opened chan struct{}) {
	for {
		stream, err := c.assoc.AcceptStream()
		if err != nil {
			if c.ctx.Err() == nil {
				go c.closeWith(fmt.Errorf("accept stream: %w", err))
			}
			return
		}
		go c.serveStream(stream, opened)
	}
}

func (c *nnConn) serveStream(stream *sctp.Stream, opened chan struct{}) {
	buf := make([]byte, maxSegment+2)
	n, ppi, err := stream.ReadSCTP(buf)
	if err != nil {
		return
	}
	label, err := parseDCEPOpen(buf[:n], ppi)
	if err != nil {
		go c.closeWith(err)
		return
	}
	if _, err := stream.WriteSCTP([]byte{dcepAck}, sctp.PayloadTypeWebRTCDCEP); err != nil {
		go c.closeWith(err)
		return
	}
	switch label {
	case labelReliable:
		if !c.reliable.stream.CompareAndSwap(nil, stream) {
			_ = stream.Close()
			return
		}
		c.openedOnce.Do(func() { close(opened) })
		for {
			n, ppi, err := stream.ReadSCTP(buf)
			if err != nil {
				if c.ctx.Err() == nil {
					go c.closeWith(fmt.Errorf("reliable channel: %w", err))
				}
				return
			}
			if ppi != sctp.PayloadTypeWebRTCBinary && ppi != sctp.PayloadTypeWebRTCBinaryEmpty {
				continue
			}
			if err := c.reliable.handle(c.ctx, append([]byte(nil), buf[:n]...)); err != nil {
				go c.closeWith(err)
				return
			}
		}
	case labelUnrel:
		for {
			if _, _, err := stream.ReadSCTP(buf); err != nil {
				return
			}
		}
	default:
		go c.closeWith(fmt.Errorf("unexpected data channel %q", label))
	}
}

// parseDCEPOpen returns the label of a DATA_CHANNEL_OPEN message.
func parseDCEPOpen(data []byte, ppi sctp.PayloadProtocolIdentifier) (string, error) {
	if ppi != sctp.PayloadTypeWebRTCDCEP || len(data) < 12 || data[0] != dcepOpen {
		return "", errors.New("first message of a stream is not DATA_CHANNEL_OPEN")
	}
	labelLen := int(binary.BigEndian.Uint16(data[8:10]))
	protoLen := int(binary.BigEndian.Uint16(data[10:12]))
	if 12+labelLen+protoLen > len(data) {
		return "", errors.New("truncated DATA_CHANNEL_OPEN")
	}
	return string(data[12 : 12+labelLen]), nil
}
