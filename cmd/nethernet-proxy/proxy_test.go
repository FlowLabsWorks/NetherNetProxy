package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // STUN
	"encoding/binary"
	"hash/crc32"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/pion/sctp"
)

// RFC 5769 test vectors (STUN request / response, short-term credential).
const rfcPassword = "VOkJxbRl1RmTxUk/WvJxBt"

var rfc5769Request = []byte("\x00\x01\x00\x58" +
	"\x21\x12\xa4\x42" +
	"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
	"\x80\x22\x00\x10" + "STUN test client" +
	"\x00\x24\x00\x04" + "\x6e\x00\x01\xff" +
	"\x80\x29\x00\x08" + "\x93\x2f\xf9\xb1\x51\x26\x3b\x36" +
	"\x00\x06\x00\x09" + "\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20" +
	"\x00\x08\x00\x14" + "\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5" + "\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2" +
	"\x80\x28\x00\x04" + "\xe5\x7a\x3b\xcf")

var rfc5769ResponseIPv4 = []byte("\x01\x01\x00\x3c" +
	"\x21\x12\xa4\x42" +
	"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
	"\x80\x22\x00\x0b" + "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20" +
	"\x00\x20\x00\x08" + "\x00\x01\xa1\x47\xe1\x12\xa6\x43" +
	"\x00\x08\x00\x14" + "\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9" + "\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7" +
	"\x80\x28\x00\x04" + "\xc0\x7d\x4c\x96")

func TestRFC5769Request(t *testing.T) {
	m, err := parseSTUN(rfc5769Request)
	if err != nil {
		t.Fatal(err)
	}
	if u := m.attr(attrUsername); u == nil || string(u.val) != "evtj:h6vY" {
		t.Fatalf("username = %v", u)
	}
	if !m.verifyIntegrity([]byte(rfcPassword)) {
		t.Fatal("MESSAGE-INTEGRITY of the RFC request does not verify")
	}
	if !m.verifyFingerprint() {
		t.Fatal("FINGERPRINT of the RFC request does not verify")
	}
	if m.verifyIntegrity([]byte("wrong password")) {
		t.Fatal("integrity verified with a wrong key")
	}
	tampered := append([]byte(nil), rfc5769Request...)
	tampered[30] ^= 0xff
	if mt, err := parseSTUN(tampered); err == nil && mt.verifyIntegrity([]byte(rfcPassword)) {
		t.Fatal("tampered message verified")
	}
}

func TestRFC5769Response(t *testing.T) {
	m, err := parseSTUN(rfc5769ResponseIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if !m.verifyIntegrity([]byte(rfcPassword)) || !m.verifyFingerprint() {
		t.Fatal("RFC response does not verify")
	}
	ip, port, err := decodeXorMapped(m.attr(attrXorMapped).val, m.tx)
	if err != nil || ip.String() != "192.0.2.1" || port != 32853 {
		t.Fatalf("mapped address = %v:%d (%v)", ip, port, err)
	}
}

func TestBuildBindingSuccess(t *testing.T) {
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 66, 71), Port: 56112}
	tx := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	resp := buildBindingSuccess(tx, from, []byte("secret-password-1234567"))
	m, err := parseSTUN(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.typ != stunBindingSuccess || m.tx != tx {
		t.Fatalf("header = %x %x", m.typ, m.tx)
	}
	if !m.verifyIntegrity([]byte("secret-password-1234567")) || !m.verifyFingerprint() {
		t.Fatal("generated response does not verify")
	}
	ip, port, err := decodeXorMapped(m.attr(attrXorMapped).val, m.tx)
	if err != nil || !ip.Equal(from.IP) || port != from.Port {
		t.Fatalf("mapped address = %v:%d (%v)", ip, port, err)
	}
}

// buildTestRequest builds a Binding request like a controlling console would.
func buildTestRequest(username string, key []byte, useCandidate bool) []byte {
	msg := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(msg[4:8], stunCookie)
	copy(msg[8:20], []byte("txid-0123456"))
	msg = appendAttr(msg, attrUsername, []byte(username))
	if useCandidate {
		msg = appendAttr(msg, attrUseCandidate, nil)
	}
	setLength(msg, len(msg)-stunHeaderLen+24)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	msg = appendAttr(msg, attrIntegrity, mac.Sum(nil))
	setLength(msg, len(msg)-stunHeaderLen+8)
	msg = appendAttr(msg, attrFingerprint, binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(msg)^0x5354554e))
	setLength(msg, len(msg)-stunHeaderLen)
	return msg
}

func TestICELiteAnswersChecks(t *testing.T) {
	l, err := newICELite(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	go l.run()

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: l.port()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// A check for another ufrag must be ignored.
	_, _ = client.Write(buildTestRequest("other:abcd", []byte(l.pwd), false))
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := client.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("got %d bytes for a foreign ufrag", n)
	}
	// A check with the wrong password must be ignored.
	_, _ = client.Write(buildTestRequest(l.ufrag+":abcd", []byte("not-the-password-123456"), false))
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := client.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("got %d bytes for a wrong password", n)
	}
	select {
	case <-l.up:
		t.Fatal("agent came up on invalid checks")
	default:
	}

	// A valid, nominating check is answered and selects the sender.
	_, _ = client.Write(buildTestRequest(l.ufrag+":abcd", []byte(l.pwd), true))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseSTUN(buf[:n])
	if err != nil || m.typ != stunBindingSuccess || !m.verifyIntegrity([]byte(l.pwd)) || !m.verifyFingerprint() {
		t.Fatalf("bad response: %v %v", m, err)
	}
	select {
	case <-l.up:
	case <-time.After(time.Second):
		t.Fatal("agent did not come up")
	}
	if got := l.selectedAddr(); got == nil || got.Port != client.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("selected = %v", got)
	}

	// DTLS packets from the selected peer reach the DTLS conn; others do not.
	pc := newLiteConn(l)
	_, _ = client.Write([]byte{22, 254, 253, 0, 0})
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	rb := make([]byte, 100)
	rn, _, err := pc.ReadFrom(rb)
	if err != nil || !bytes.Equal(rb[:rn], []byte{22, 254, 253, 0, 0}) {
		t.Fatalf("DTLS read = %v %v", rb[:rn], err)
	}
	// And the other way round.
	if _, err := pc.WriteTo([]byte{23, 1, 2, 3}, nil); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if n, err = client.Read(buf); err != nil || !bytes.Equal(buf[:n], []byte{23, 1, 2, 3}) {
		t.Fatalf("DTLS write = %v %v", buf[:n], err)
	}
}

func TestLocalCandidatesFormat(t *testing.T) {
	candidates, err := localCandidates(4242, "uf")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range candidates {
		if len(c) < 40 || c[:12] != "a=candidate:" {
			t.Fatalf("odd candidate %q", c)
		}
	}
}

func TestParseDCEPOpen(t *testing.T) {
	open := []byte{dcepOpen, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(labelReliable)) >> 8, 0, 0}
	binary.BigEndian.PutUint16(open[8:10], uint16(len(labelReliable)))
	open = append(open, labelReliable...)
	label, err := parseDCEPOpen(open, sctp.PayloadTypeWebRTCDCEP)
	if err != nil || label != labelReliable {
		t.Fatalf("label = %q (%v)", label, err)
	}
	if _, err := parseDCEPOpen(open, sctp.PayloadTypeWebRTCBinary); err == nil {
		t.Fatal("accepted a DCEP open with the wrong PPID")
	}
	if _, err := parseDCEPOpen(open[:10], sctp.PayloadTypeWebRTCDCEP); err == nil {
		t.Fatal("accepted a truncated DCEP open")
	}
}

func TestSegmentReassembly(t *testing.T) {
	r := &reliableChannel{packets: make(chan []byte, 2)}
	ctx := context.Background()
	if err := r.handle(ctx, append([]byte{2}, "ab"...)); err != nil {
		t.Fatal(err)
	}
	if err := r.handle(ctx, append([]byte{1}, "cd"...)); err != nil {
		t.Fatal(err)
	}
	if err := r.handle(ctx, append([]byte{0}, "ef"...)); err != nil {
		t.Fatal(err)
	}
	if got := <-r.packets; string(got) != "abcdef" {
		t.Fatalf("reassembled %q", got)
	}
	// A wrong counter is an error.
	if err := r.handle(ctx, append([]byte{3}, "x"...)); err != nil {
		t.Fatal(err)
	}
	if err := r.handle(ctx, append([]byte{0}, "y"...)); err == nil {
		t.Fatal("accepted a segment with a broken counter")
	}
}

func TestBedrockBatchRoundTrip(t *testing.T) {
	frames := []frame{{idPlayStatus, tplPlayStatusOK}, {idResourcePackStack, tplPackStack}}
	for _, compressed := range []bool{false, true} {
		b, err := encodeBatch(frames, compressed)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeBatch(b, compressed)
		if err != nil || len(got) != 2 || got[0].id != idPlayStatus || !bytes.Equal(got[1].payload, tplPackStack) {
			t.Fatalf("compressed=%v: %v %v", compressed, got, err)
		}
	}
}

func TestDiscoveryPacketRoundTrip(t *testing.T) {
	sealed := buildMessage(111, 222, "CONNECTREQUEST 5 hello world")
	pk, err := openPacket(sealed)
	if err != nil || pk.kind != pktMessage || pk.sender != 111 || pk.recipient != 222 || pk.data != "CONNECTREQUEST 5 hello world" {
		t.Fatalf("%+v %v", pk, err)
	}
	sig, err := parseSignal(pk.data)
	if err != nil || sig.typ != sigOffer || sig.connID != 5 || sig.data != "hello world" {
		t.Fatalf("%+v %v", sig, err)
	}
	if _, err := openPacket(append([]byte(nil), sealed[:len(sealed)-16]...)); err == nil {
		t.Fatal("accepted a truncated packet")
	}
}
