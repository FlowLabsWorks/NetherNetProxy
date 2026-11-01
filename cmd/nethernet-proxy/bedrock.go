package main

// A deliberately tiny Bedrock "server": just enough of the login sequence for a console to
// believe it has joined a world, followed by a Transfer packet to the real server.
//
// The packets below the console needs before it processes a Transfer were recorded from a
// working session (Minecraft 1.26.60, protocol 2225) and are replayed as templates. Only the
// Transfer packet is built dynamically. Nothing from the Login packet is trusted or stored.

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// Packet IDs used in the sequence.
const (
	idLogin                       = 1
	idPlayStatus                  = 2
	idResourcePacksInfo           = 6
	idResourcePackStack           = 7
	idResourcePackClientResponse  = 8
	idStartGame                   = 11
	idRequestChunkRadius          = 69
	idChunkRadiusUpdated          = 70
	idTransfer                    = 85
	idSetLocalPlayerAsInitialised = 113
	idClientCacheStatus           = 129
	idPlayerAuthInput             = 144
	idUnknown145                  = 145
	idItemRegistry                = 162
	idUnknown313                  = 313
	idUnknown337                  = 337
	idRequestNetworkSettings      = 193
	idNetworkSettings             = 143
)

const (
	compressionThreshold = 256
	maxBatchSize         = 4 << 20
	sessionTimeout       = 45 * time.Second
)

// Server packet payloads recorded from a working session. The StartGame world name is
// "transfer" (same length as the recorded name, so the layout is unchanged).
var (
	tplNetworkSettings = mustHex("00010000000000000000") // threshold 256, flate, no throttling
	tplPlayStatusOK    = mustHex("00000000")             // LoginSuccess
	tplPlayStatusSpawn = mustHex("00000003")             // PlayerSpawn
	tplPacksInfo       = make([]byte, 22)                // no packs, nothing forced
	tplPackStack       = mustHex("00082464333463666134622d326164312d343533642d613064622d36363862343239613365613007312e32362e3430002462343163323738352d633531322d346134392d616635362d33613837616664343763353707312e32312e3330002461346466306362332d313762652d343136332d383864372d66636637303032623933356407312e32312e3230002464313961646666652d613265312d346230322d383433362d63613435383333363863383907312e32312e3130002438356435363033642d323832342d346232312d383034342d33346634343166346663653106312e32312e30002465393737636431332d306131312d343631382d393666622d30336466653963343336303807312e32302e3630002430363734373231632d613061612d343161312d396261382d31656433336561336537656407312e32302e3530002430666261343036332d646261312d343238312d396238392d66663933393036353335333005312e302e300007312e32362e3630010000000763616d65726173010000")
	tpl313             = mustHex("0a00090a70726f636573736f72730a00090e74656d706c6174655f706f6f6c730a0009076a6967736177730a00090e7374727563747572655f736574730a0000")
	tpl337             = mustHex("00000000")
	// The recorded world name "survival" is swapped for "transfer" (same length).
	tplStartGame = mustHex(strings.Replace("000000000000000000000000000000000000000000000000000000000000000000000002000000000000010000000000000100000000000000000000010100000100000000000000000000000000000000000000000000000000000000000000000000000000000000000008737572766976616c00000000000000000000000000002430353632666435302d363964652d346230302d623632612d3666323861353063366138320007312e32362e36300a00000000000000000000000000000000000000000000000000000000000000000000",
		"737572766976616c", "7472616e73666572", 1))
	tplItemRegistry = mustHex("00")
	tplChunkRadius  = mustHex("20")
	tpl145          = mustHex("0000")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type frame struct {
	id      uint32
	payload []byte
}

func putUvarint32(buf *bytes.Buffer, v uint32) {
	for v >= 0x80 {
		buf.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	buf.WriteByte(byte(v))
}

func readUvarint32(b []byte) (uint32, int, error) {
	var v uint32
	for i := 0; i < 5 && i < len(b); i++ {
		v |= uint32(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("bad varuint32")
}

// encodeBatch serialises frames into one NetherNet message. compressed selects the format used
// after NetworkSettings: a leading algorithm byte, flate for batches above the threshold.
func encodeBatch(frames []frame, compressed bool) ([]byte, error) {
	var body bytes.Buffer
	for _, f := range frames {
		var pk bytes.Buffer
		putUvarint32(&pk, f.id) // sub-client IDs are always 0 here
		pk.Write(f.payload)
		putUvarint32(&body, uint32(pk.Len()))
		body.Write(pk.Bytes())
	}
	if !compressed {
		return body.Bytes(), nil
	}
	if body.Len() < compressionThreshold {
		return append([]byte{0xff}, body.Bytes()...), nil
	}
	var out bytes.Buffer
	out.WriteByte(0) // flate
	w, err := flate.NewWriter(&out, 6)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(body.Bytes()); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decodeBatch(data []byte, compressed bool) ([]frame, error) {
	if compressed {
		if len(data) == 0 {
			return nil, errors.New("empty batch")
		}
		switch data[0] {
		case 0xff:
			data = data[1:]
		case 0:
			r := flate.NewReader(bytes.NewReader(data[1:]))
			plain, err := io.ReadAll(io.LimitReader(r, maxBatchSize+1))
			_ = r.Close()
			if err != nil {
				return nil, fmt.Errorf("inflate: %w", err)
			}
			if len(plain) > maxBatchSize {
				return nil, errors.New("batch too large")
			}
			data = plain
		default:
			return nil, fmt.Errorf("unsupported compression %d", data[0])
		}
	}
	var frames []frame
	for len(data) > 0 {
		length, n, err := readUvarint32(data)
		if err != nil || int(length) > len(data)-n || length == 0 {
			return nil, errors.New("bad packet length")
		}
		pk := data[n : n+int(length)]
		data = data[n+int(length):]
		header, hn, err := readUvarint32(pk)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame{id: header & 0x3ff, payload: pk[hn:]})
	}
	return frames, nil
}

func transferPayload(host string, port uint16) []byte {
	var b bytes.Buffer
	putUvarint32(&b, uint32(len(host)))
	b.WriteString(host)
	_ = binary.Write(&b, binary.LittleEndian, port)
	b.WriteByte(0) // reload world
	b.WriteByte(0) // no gathering join info
	return b.Bytes()
}

// packetConn is a connection that exchanges whole Bedrock batches.
type packetConn interface {
	ReadPacket() ([]byte, error)
	Write([]byte) (int, error)
	Close() error
}

// serveTransfer runs the handshake on conn and finishes with a Transfer packet to host:port.
// It returns when the console has been sent on its way, or on error or timeout.
func serveTransfer(conn packetConn, host string, port uint16, log *slog.Logger, dump bool) error {
	timer := time.AfterFunc(sessionTimeout, func() { _ = conn.Close() })
	defer timer.Stop()

	compressed := false
	send := func(frames ...frame) error {
		b, err := encodeBatch(frames, compressed)
		if err != nil {
			return err
		}
		if dump {
			for _, f := range frames {
				log.Debug("pkt out", "id", f.id, "bytes", len(f.payload))
			}
		}
		_, err = conn.Write(b)
		return err
	}

	for {
		data, err := conn.ReadPacket()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		frames, err := decodeBatch(data, compressed)
		if err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		for _, f := range frames {
			if dump && f.id != idPlayerAuthInput {
				log.Debug("pkt in", "id", f.id, "bytes", len(f.payload))
			}
			switch f.id {
			case idRequestNetworkSettings:
				if len(f.payload) >= 4 {
					log.Info("client protocol", "protocol", binary.BigEndian.Uint32(f.payload))
				}
				// Sent in the old format, compression applies to everything after it.
				if err := send(frame{idNetworkSettings, tplNetworkSettings}); err != nil {
					return err
				}
				compressed = true
			case idLogin:
				// The Login packet is ignored on purpose: the real server authenticates the
				// console after the transfer.
				if err := send(frame{idPlayStatus, tplPlayStatusOK}); err != nil {
					return err
				}
				if err := send(frame{idResourcePacksInfo, tplPacksInfo}); err != nil {
					return err
				}
			case idResourcePackClientResponse:
				if len(f.payload) == 0 {
					return errors.New("empty resource pack response")
				}
				// The response is a varuint32 (0 refused, 1 send packs, 2 all packs downloaded,
				// 3 stack finished) followed by its name as a string.
				switch f.payload[0] {
				case 0: // refused
					return errors.New("console refused resource packs")
				case 3: // stack finished
					if err := send(
						frame{idUnknown313, tpl313},
						frame{idUnknown337, tpl337},
						frame{idStartGame, tplStartGame},
						frame{idItemRegistry, tplItemRegistry},
					); err != nil {
						return err
					}
				default: // 1: send packs (none offered), 2: all packs downloaded
					if err := send(frame{idResourcePackStack, tplPackStack}); err != nil {
						return err
					}
				}
			case idRequestChunkRadius:
				if err := send(
					frame{idChunkRadiusUpdated, tplChunkRadius},
					frame{idPlayStatus, tplPlayStatusSpawn},
					frame{idUnknown145, tpl145},
				); err != nil {
					return err
				}
			case idSetLocalPlayerAsInitialised:
				if err := send(frame{idTransfer, transferPayload(host, port)}); err != nil {
					return err
				}
				time.Sleep(3 * time.Second) // let the console process it before we hang up
				return nil
			}
		}
	}
}
