package main

// The few STUN (RFC 5389) pieces an ICE-lite agent needs: parse a Binding request, check its
// USERNAME / MESSAGE-INTEGRITY / FINGERPRINT, and build the Binding success response.

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // mandated by STUN MESSAGE-INTEGRITY
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
)

const (
	stunCookie         uint32 = 0x2112A442
	stunBindingRequest uint16 = 0x0001
	stunBindingSuccess uint16 = 0x0101

	attrUsername     uint16 = 0x0006
	attrIntegrity    uint16 = 0x0008
	attrXorMapped    uint16 = 0x0020
	attrUseCandidate uint16 = 0x0025
	attrFingerprint  uint16 = 0x8028

	stunHeaderLen = 20
)

type stunAttr struct {
	typ uint16
	val []byte
	off int // offset of the attribute header inside the message
}

type stunMsg struct {
	typ   uint16
	tx    [12]byte
	attrs []stunAttr
	raw   []byte
}

func (m *stunMsg) attr(t uint16) *stunAttr {
	for i := range m.attrs {
		if m.attrs[i].typ == t {
			return &m.attrs[i]
		}
	}
	return nil
}

func parseSTUN(b []byte) (*stunMsg, error) {
	if len(b) < stunHeaderLen || b[0]&0xC0 != 0 {
		return nil, errors.New("not a STUN message")
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length%4 != 0 || len(b) != stunHeaderLen+length {
		return nil, errors.New("bad STUN length")
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunCookie {
		return nil, errors.New("bad STUN cookie")
	}
	m := &stunMsg{typ: binary.BigEndian.Uint16(b[0:2]), raw: b}
	copy(m.tx[:], b[8:20])
	for off := stunHeaderLen; off < len(b); {
		if off+4 > len(b) {
			return nil, errors.New("truncated STUN attribute")
		}
		t := binary.BigEndian.Uint16(b[off:])
		l := int(binary.BigEndian.Uint16(b[off+2:]))
		next := off + 4 + (l+3)&^3
		if off+4+l > len(b) || next > len(b) {
			return nil, errors.New("STUN attribute overruns message")
		}
		m.attrs = append(m.attrs, stunAttr{typ: t, val: b[off+4 : off+4+l], off: off})
		off = next
	}
	return m, nil
}

// verifyIntegrity checks MESSAGE-INTEGRITY with the short-term credential key (the ICE password).
func (m *stunMsg) verifyIntegrity(key []byte) bool {
	a := m.attr(attrIntegrity)
	if a == nil || len(a.val) != sha1.Size {
		return false
	}
	msg := append([]byte(nil), m.raw[:a.off]...)
	// The length field must cover everything up to and including MESSAGE-INTEGRITY.
	binary.BigEndian.PutUint16(msg[2:4], uint16(a.off-stunHeaderLen+4+sha1.Size))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	return hmac.Equal(mac.Sum(nil), a.val)
}

// verifyFingerprint checks FINGERPRINT when present (it is optional in ICE checks).
func (m *stunMsg) verifyFingerprint() bool {
	a := m.attr(attrFingerprint)
	if a == nil {
		return true
	}
	if len(a.val) != 4 || a.off+8 != len(m.raw) { // must be the last attribute
		return false
	}
	msg := append([]byte(nil), m.raw[:a.off]...)
	binary.BigEndian.PutUint16(msg[2:4], uint16(a.off-stunHeaderLen+8))
	return crc32.ChecksumIEEE(msg)^0x5354554e == binary.BigEndian.Uint32(a.val)
}

func appendAttr(msg []byte, t uint16, val []byte) []byte {
	msg = binary.BigEndian.AppendUint16(msg, t)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(val)))
	msg = append(msg, val...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}
	return msg
}

func setLength(msg []byte, n int) { binary.BigEndian.PutUint16(msg[2:4], uint16(n)) }

// buildBindingSuccess answers a Binding request: XOR-MAPPED-ADDRESS, then MESSAGE-INTEGRITY with
// key and FINGERPRINT.
func buildBindingSuccess(tx [12]byte, from *net.UDPAddr, key []byte) []byte {
	msg := make([]byte, stunHeaderLen, 96)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint32(msg[4:8], stunCookie)
	copy(msg[8:20], tx[:])

	cookie := binary.BigEndian.AppendUint32(nil, stunCookie)
	xorKey := append(cookie, tx[:]...)
	var val []byte
	if ip4 := from.IP.To4(); ip4 != nil {
		val = []byte{0, 1}
		val = binary.BigEndian.AppendUint16(val, uint16(from.Port)^uint16(stunCookie>>16))
		for i := 0; i < 4; i++ {
			val = append(val, ip4[i]^xorKey[i])
		}
	} else {
		ip6 := from.IP.To16()
		val = []byte{0, 2}
		val = binary.BigEndian.AppendUint16(val, uint16(from.Port)^uint16(stunCookie>>16))
		for i := 0; i < 16; i++ {
			val = append(val, ip6[i]^xorKey[i])
		}
	}
	msg = appendAttr(msg, attrXorMapped, val)

	setLength(msg, len(msg)-stunHeaderLen+4+sha1.Size)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	msg = appendAttr(msg, attrIntegrity, mac.Sum(nil))

	setLength(msg, len(msg)-stunHeaderLen+8)
	crc := crc32.ChecksumIEEE(msg) ^ 0x5354554e
	msg = appendAttr(msg, attrFingerprint, binary.BigEndian.AppendUint32(nil, crc))
	setLength(msg, len(msg)-stunHeaderLen)
	return msg
}

// decodeXorMapped reads an XOR-MAPPED-ADDRESS value (used by tests).
func decodeXorMapped(val []byte, tx [12]byte) (net.IP, int, error) {
	if len(val) < 8 {
		return nil, 0, errors.New("short address")
	}
	cookie := binary.BigEndian.AppendUint32(nil, stunCookie)
	xorKey := append(cookie, tx[:]...)
	port := int(binary.BigEndian.Uint16(val[2:4]) ^ uint16(stunCookie>>16))
	n := 4
	if val[1] == 2 {
		n = 16
	}
	if len(val) < 4+n {
		return nil, 0, errors.New("short address")
	}
	ip := make(net.IP, n)
	for i := 0; i < n; i++ {
		ip[i] = val[4+i] ^ xorKey[i]
	}
	return ip, port, nil
}
