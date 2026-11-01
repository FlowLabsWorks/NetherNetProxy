package main

// A small NetherNet implementation: only what a LAN host needs.
//
//   - LAN discovery (UDP 7551): AES-ECB + HMAC sealed packets (Request / Response / Message),
//     the "ServerData" world card and the signaling message format.
//   - Answering a WebRTC offer from a client without identity: see session.go and icelite.go.
//
// The wire formats follow the NetherNet notes of df-mc/nethernet-spec and the behaviour of
// df-mc/go-nethernet (MIT).

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// -- LAN discovery -----------------------------------------------------------------------

const (
	pktRequest  uint16 = 0
	pktResponse uint16 = 1
	pktMessage  uint16 = 2
)

// discoveryKey is derived from the application ID 0xdeadbeef used by all vanilla clients.
var discoveryKey = sha256.Sum256(binary.LittleEndian.AppendUint64(nil, 0xdeadbeef))

func ecbCrypt(src []byte, encrypt bool) []byte {
	block, _ := aes.NewCipher(discoveryKey[:])
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += block.BlockSize() {
		if encrypt {
			block.Encrypt(dst[i:], src[i:])
		} else {
			block.Decrypt(dst[i:], src[i:])
		}
	}
	return dst
}

func sealPacket(kind uint16, sender uint64, body []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, kind)
	_ = binary.Write(&buf, binary.LittleEndian, sender)
	buf.Write(make([]byte, 8))
	buf.Write(body)
	payload := binary.LittleEndian.AppendUint16(nil, uint16(buf.Len()+2))
	payload = append(payload, buf.Bytes()...)

	pad := aes.BlockSize - len(payload)%aes.BlockSize // PKCS#7
	padded := append(append([]byte(nil), payload...), bytes.Repeat([]byte{byte(pad)}, pad)...)

	mac := hmac.New(sha256.New, discoveryKey[:])
	mac.Write(payload)
	return append(mac.Sum(nil), ecbCrypt(padded, true)...)
}

type discoveryPacket struct {
	kind      uint16
	sender    uint64
	recipient uint64 // messages only
	data      string // messages only
}

func openPacket(b []byte) (discoveryPacket, error) {
	var pk discoveryPacket
	if len(b) < 32+aes.BlockSize || (len(b)-32)%aes.BlockSize != 0 {
		return pk, errors.New("bad packet length")
	}
	padded := ecbCrypt(b[32:], false)
	pad := int(padded[len(padded)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(padded) {
		return pk, errors.New("bad padding")
	}
	payload := padded[:len(padded)-pad]
	mac := hmac.New(sha256.New, discoveryKey[:])
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), b[:32]) {
		return pk, errors.New("checksum mismatch")
	}
	if len(payload) < 2+18 {
		return pk, io.ErrUnexpectedEOF
	}
	r := bytes.NewReader(payload[2:])
	_ = binary.Read(r, binary.LittleEndian, &pk.kind)
	_ = binary.Read(r, binary.LittleEndian, &pk.sender)
	_, _ = r.Seek(8, io.SeekCurrent)
	if pk.kind == pktMessage {
		var n uint32
		if err := binary.Read(r, binary.LittleEndian, &pk.recipient); err != nil {
			return pk, err
		}
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return pk, err
		}
		rest, _ := io.ReadAll(r)
		// Vanilla may write more than the declared length; the signal simply continues.
		pk.data = string(rest)
		if int(n) > len(rest) {
			return pk, errors.New("message shorter than declared")
		}
	}
	return pk, nil
}

func buildResponse(sender uint64, card []byte) []byte {
	h := make([]byte, hex.EncodedLen(len(card))) // the world card is sent as hex text
	hex.Encode(h, card)
	body := binary.LittleEndian.AppendUint32(nil, uint32(len(h)))
	body = append(body, h...)
	return sealPacket(pktResponse, sender, body)
}

func buildMessage(sender, recipient uint64, data string) []byte {
	body := binary.LittleEndian.AppendUint64(nil, recipient)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, data...)
	return sealPacket(pktMessage, sender, body)
}

// serverCard is the "ServerData" world card shown in the LAN list (version 7).
type serverCard struct {
	Name, Version, Level, Nonce string
	Protocol, Players, Max      int32
	GameType                    int32
}

func (c serverCard) marshal() []byte {
	var b bytes.Buffer
	b.WriteByte(7)
	putString(&b, c.Name)
	putVarint32(&b, c.Protocol)
	putString(&b, c.Version)
	putString(&b, c.Level)
	putVarint32(&b, c.Players)
	putVarint32(&b, c.Max)
	putVarint32(&b, c.GameType)
	b.WriteByte(0) // editor world
	b.WriteByte(0) // hardcore
	b.WriteByte(1) // accepts online auth
	b.WriteByte(1) // accepts self-signed auth
	putString(&b, c.Nonce)
	putVarint32(&b, 4) // connection type: LAN
	return b.Bytes()
}

func putString(b *bytes.Buffer, s string) {
	putUvarint32(b, uint32(len(s)))
	b.WriteString(s)
}

func putVarint32(b *bytes.Buffer, v int32) {
	u := uint32(v) << 1
	if v < 0 {
		u = ^u
	}
	putUvarint32(b, u)
}

// -- signaling messages -------------------------------------------------------------------

const (
	sigOffer     = "CONNECTREQUEST"
	sigAnswer    = "CONNECTRESPONSE"
	sigCandidate = "CANDIDATEADD"
	sigError     = "CONNECTERROR"
)

type signal struct {
	typ    string
	connID uint64
	data   string
}

func (s signal) String() string { return s.typ + " " + strconv.FormatUint(s.connID, 10) + " " + s.data }

func parseSignal(text string) (signal, error) {
	parts := strings.SplitN(text, " ", 3)
	if len(parts) != 3 {
		return signal{}, errors.New("malformed signal")
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return signal{}, err
	}
	switch parts[0] {
	case sigOffer, sigAnswer, sigCandidate, sigError:
		return signal{typ: parts[0], connID: id, data: parts[2]}, nil
	}
	return signal{}, fmt.Errorf("unknown signal %q", parts[0])
}

// Error codes sent in CONNECTERROR (ESessionError).
const (
	errCodeCreatePeerConnection = 4
	errCodeICE                  = 5
	errCodeSetRemoteDescription = 13
	errCodeCreateAnswer         = 15
)
