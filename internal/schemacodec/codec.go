// Package schemacodec decodes and encodes Bedrock packet payloads from the JSON schemas Mojang
// publishes in github.com/Mojang/bedrock-protocol-docs. It exists to answer one question: if a
// packet recorded under one protocol version were written under another, would its bytes change?
//
// The schemas describe fields, order and types; the wire rules (varints, zigzag, little endian
// unless "Big Endian", length prefixes, presence bytes for optional fields) are implemented here.
// Only the constructs the replayed packets use are supported; anything else is an error.
package schemacodec

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
)

// Source provides the schema files of one protocol version by name, for example
// "StartGamePacket.json".
type Source interface {
	File(name string) ([]byte, error)
}

// Codec reads and writes payloads according to the schemas of one protocol version.
type Codec struct {
	c *codec
}

// New returns a codec for the schemas that src provides.
func New(src Source) *Codec {
	return &Codec{c: &codec{s: newSchemas(src)}}
}

// Decode reads a packet payload (without the packet header) into a value tree. It fails if the
// payload does not fit the schema or bytes are left over.
func (c *Codec) Decode(packet string, payload []byte) (any, error) {
	n, err := c.c.s.load(packet + ".json")
	if err != nil {
		return nil, err
	}
	r := &reader{b: payload}
	v, err := c.c.decode(r, n)
	if err != nil {
		return nil, fmt.Errorf("at byte %d: %w", r.i, err)
	}
	if r.i != len(payload) {
		return nil, fmt.Errorf("%d trailing bytes after byte %d", len(payload)-r.i, r.i)
	}
	return v, nil
}

// Encode writes a value tree as a payload. Fields the value does not have are written with the
// schema's default; fields the schema does not have are dropped. Both are listed in notes.
func (c *Codec) Encode(packet string, v any) (payload []byte, notes []string, err error) {
	n, err := c.c.s.load(packet + ".json")
	if err != nil {
		return nil, nil, err
	}
	enc := &codec{s: c.c.s}
	var w bytes.Buffer
	if err := enc.encode(&w, n, v, ""); err != nil {
		return nil, enc.notes, err
	}
	return w.Bytes(), enc.notes, nil
}

// schemas loads and caches the schema files of one version.
type schemas struct {
	src   Source
	cache map[string]node
}

func newSchemas(src Source) *schemas {
	return &schemas{src: src, cache: map[string]node{}}
}

// node is one decoded JSON schema node.
type node = map[string]any

func (s *schemas) load(file string) (node, error) {
	if n, ok := s.cache[file]; ok {
		return n, nil
	}
	b, err := s.src.File(file)
	if err != nil {
		return nil, err
	}
	var n node
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	s.cache[file] = n
	return n, nil
}

// eff resolves a node's $ref: the referenced schema with the node's own keys laid over it, which
// is how properties add serialization options to a shared type.
func (s *schemas) eff(n node) (node, error) {
	ref, ok := n["$ref"].(string)
	if !ok {
		return n, nil
	}
	file, err := url.PathUnescape(strings.TrimPrefix(strings.SplitN(ref, "#", 2)[0], "./"))
	if err != nil {
		return nil, err
	}
	base, err := s.load(file)
	if err != nil {
		return nil, err
	}
	base, err = s.eff(base)
	if err != nil {
		return nil, err
	}
	out := node{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range n {
		if k != "$ref" {
			out[k] = v
		}
	}
	return out, nil
}

func optionSet(n node) map[string]bool {
	set := map[string]bool{}
	if l, ok := n["x-serialization-options"].([]any); ok {
		for _, o := range l {
			if s, ok := o.(string); ok {
				set[s] = true
			}
		}
	}
	return set
}

func str(n node, key string) string {
	s, _ := n[key].(string)
	return s
}

type field struct {
	name string
	node node
}

// fields returns an object's properties in wire order.
func fields(n node) []field {
	props, _ := n["properties"].(map[string]any)
	out := make([]field, 0, len(props))
	for name, p := range props {
		pn, _ := p.(node)
		out = append(out, field{name, pn})
	}
	ord := func(f field) float64 { v, _ := f.node["x-ordinal-index"].(float64); return v }
	sort.Slice(out, func(i, j int) bool {
		if ord(out[i]) != ord(out[j]) {
			return ord(out[i]) < ord(out[j])
		}
		return out[i].name < out[j].name
	})
	return out
}

func intInfo(u string) (size int, signed, ok bool) {
	switch u {
	case "int8":
		return 1, true, true
	case "uint8":
		return 1, false, true
	case "int16":
		return 2, true, true
	case "uint16":
		return 2, false, true
	case "int32":
		return 4, true, true
	case "uint32":
		return 4, false, true
	case "int64":
		return 8, true, true
	case "uint64":
		return 8, false, true
	}
	return 0, false, false
}

// Value model: objects are map[string]any, arrays []any, signed integers int64, unsigned ones
// uint64, floats float64, plus the two special types below.
type (
	rawNBT   []byte // a network NBT tag, kept as bytes
	oneOfVal struct {
		index uint64
		value any
	}
)

// absentVal is the value of an optional field that was not present.
type absentVal struct{}

// optionalField reports whether a property is written with a presence byte: the schema lists the
// mandatory ones in "required", and an object without that list has only mandatory fields.
func optionalField(n node, name string) bool {
	req, ok := n["required"].([]any)
	if !ok {
		return false
	}
	for _, r := range req {
		if r == name {
			return false
		}
	}
	return true
}

type reader struct {
	b []byte
	i int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, fmt.Errorf("need %d bytes at offset %d, %d left", n, r.i, len(r.b)-r.i)
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out, nil
}

func (r *reader) varuint() (uint64, error) {
	var v uint64
	for shift := 0; shift < 70; shift += 7 {
		b, err := r.take(1)
		if err != nil {
			return 0, err
		}
		v |= uint64(b[0]&0x7f) << shift
		if b[0]&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errors.New("varint too long")
}

func putVaruint(w *bytes.Buffer, v uint64) {
	for v >= 0x80 {
		w.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	w.WriteByte(byte(v))
}

func zigzag(v int64) uint64   { return uint64(v<<1) ^ uint64(v>>63) }
func unzigzag(v uint64) int64 { return int64(v>>1) ^ -int64(v&1) }

// codec decodes bytes into values and encodes values into bytes, both driven by a schema. When a
// value is missing for a field of the target schema, the schema's default (or zero) is written and
// the decision is recorded in notes.
type codec struct {
	s     *schemas
	notes []string
}

func (c *codec) note(format string, args ...any) {
	c.notes = append(c.notes, fmt.Sprintf(format, args...))
}

func (c *codec) decode(r *reader, n node) (any, error) {
	n, err := c.s.eff(n)
	if err != nil {
		return nil, err
	}
	u := str(n, "x-underlying-type")
	typ := str(n, "type")
	opts := optionSet(n)

	switch {
	case n["oneOf"] != nil:
		return c.decodeOneOf(r, n)
	case u == "boolean" || typ == "boolean":
		b, err := r.take(1)
		if err != nil {
			return nil, err
		}
		return b[0] != 0, nil
	case u == "float":
		b, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), nil
	case u == "double":
		b, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), nil
	case u != "" && u != "object":
		size, signed, ok := intInfo(u)
		if !ok {
			return nil, fmt.Errorf("unknown underlying type %q", u)
		}
		return decodeInt(r, size, signed, opts)
	case typ == "string":
		return c.decodeString(r, opts)
	case typ == "array":
		return c.decodeArray(r, n)
	case typ == "object" && n["properties"] != nil:
		out := map[string]any{}
		for _, f := range fields(n) {
			if optionalField(n, f.name) {
				b, err := r.take(1)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", f.name, err)
				}
				if b[0] == 0 {
					out[f.name] = absentVal{}
					continue
				}
			}
			v, err := c.decode(r, f.node)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.name, err)
			}
			out[f.name] = v
		}
		return out, nil
	case typ == "object" && n["additionalProperties"] != nil:
		return c.decodeMap(r, n)
	case typ == "":
		return decodeNBT(r)
	}
	return nil, fmt.Errorf("unsupported schema node (type %q, underlying %q)", typ, u)
}

func decodeInt(r *reader, size int, signed bool, opts map[string]bool) (any, error) {
	if opts["Compression"] {
		v, err := r.varuint()
		if err != nil {
			return nil, err
		}
		if signed {
			return unzigzag(v), nil
		}
		return v, nil
	}
	b, err := r.take(size)
	if err != nil {
		return nil, err
	}
	var v uint64
	if opts["Big Endian"] {
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
	} else {
		for i := size - 1; i >= 0; i-- {
			v = v<<8 | uint64(b[i])
		}
	}
	if signed {
		shift := uint(64 - 8*size)
		return int64(v<<shift) >> shift, nil
	}
	return v, nil
}

func (c *codec) length(r *reader, opts map[string]bool) (int, error) {
	if opts["No size compression"] {
		b, err := r.take(4)
		if err != nil {
			return 0, err
		}
		return int(binary.LittleEndian.Uint32(b)), nil
	}
	v, err := r.varuint()
	if v > 1<<24 {
		return 0, fmt.Errorf("implausible length %d", v)
	}
	return int(v), err
}

func (c *codec) decodeString(r *reader, opts map[string]bool) (any, error) {
	n, err := c.length(r, opts)
	if err != nil {
		return nil, err
	}
	b, err := r.take(n)
	return string(b), err
}

func (c *codec) decodeArray(r *reader, n node) (any, error) {
	items, _ := n["items"].(node)
	count, err := c.length(r, optionSet(n))
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, count)
	for i := 0; i < count; i++ {
		v, err := c.decode(r, items)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// decodeMap reads a map as a counted list of key/value pairs.
func (c *codec) decodeMap(r *reader, n node) (any, error) {
	entry, _ := n["additionalProperties"].(node)
	count, err := c.length(r, optionSet(n))
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, count)
	for i := 0; i < count; i++ {
		v, err := c.decode(r, entry)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// decodeOneOf reads the control value and then the alternative it selects. The control value is
// documented as x-control-value-type; it is assumed to be a plain varint.
func (c *codec) decodeOneOf(r *reader, n node) (any, error) {
	alts, _ := n["oneOf"].([]any)
	idx, err := r.varuint()
	if err != nil {
		return nil, err
	}
	if int(idx) >= len(alts) {
		return nil, fmt.Errorf("oneOf index %d out of %d", idx, len(alts))
	}
	alt, _ := alts[idx].(node)
	if str(alt, "type") == "null" {
		return oneOfVal{idx, nil}, nil
	}
	v, err := c.decode(r, alt)
	return oneOfVal{idx, v}, err
}

// decodeNBT keeps one network-format NBT tag (type, name, payload) as raw bytes.
func decodeNBT(r *reader) (any, error) {
	start := r.i
	t, err := r.take(1)
	if err != nil {
		return nil, err
	}
	if t[0] != 0 {
		n, err := r.varuint()
		if err != nil {
			return nil, err
		}
		if _, err := r.take(int(n)); err != nil {
			return nil, err
		}
		if err := skipNBT(r, t[0]); err != nil {
			return nil, err
		}
	}
	return rawNBT(append([]byte(nil), r.b[start:r.i]...)), nil
}

func skipNBT(r *reader, tag byte) error {
	switch tag {
	case 1:
		_, err := r.take(1)
		return err
	case 2:
		_, err := r.take(2)
		return err
	case 3, 4:
		_, err := r.varuint()
		return err
	case 5:
		_, err := r.take(4)
		return err
	case 6:
		_, err := r.take(8)
		return err
	case 7, 11, 12:
		n, err := r.varuint()
		if err != nil {
			return err
		}
		for i := uint64(0); i < unzigzagLen(n); i++ {
			if tag == 7 {
				_, err = r.take(1)
			} else {
				_, err = r.varuint()
			}
			if err != nil {
				return err
			}
		}
		return nil
	case 8:
		n, err := r.varuint()
		if err != nil {
			return err
		}
		_, err = r.take(int(n))
		return err
	case 9:
		et, err := r.take(1)
		if err != nil {
			return err
		}
		n, err := r.varuint()
		if err != nil {
			return err
		}
		for i := uint64(0); i < unzigzagLen(n); i++ {
			if err := skipNBT(r, et[0]); err != nil {
				return err
			}
		}
		return nil
	case 10:
		for {
			t, err := r.take(1)
			if err != nil {
				return err
			}
			if t[0] == 0 {
				return nil
			}
			n, err := r.varuint()
			if err != nil {
				return err
			}
			if _, err := r.take(int(n)); err != nil {
				return err
			}
			if err := skipNBT(r, t[0]); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("unknown NBT tag %d", tag)
}

// unzigzagLen reads an NBT array length: network NBT stores them as zigzag varints.
func unzigzagLen(v uint64) uint64 {
	n := unzigzag(v)
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// encode writes v as described by n. A nil v means "no value": the default is written.
func (c *codec) encode(w *bytes.Buffer, n node, v any, path string) error {
	n, err := c.s.eff(n)
	if err != nil {
		return err
	}
	u := str(n, "x-underlying-type")
	typ := str(n, "type")
	opts := optionSet(n)

	if _, absent := v.(absentVal); absent {
		v = nil
	}
	if v == nil {
		v, err = c.zero(n)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		c.note("added %s = %s", path, brief(v))
	}

	switch {
	case n["oneOf"] != nil:
		return c.encodeOneOf(w, n, v, path)
	case u == "boolean" || typ == "boolean":
		b, _ := toInt(v)
		if b != 0 {
			b = 1
		}
		w.WriteByte(byte(b))
	case u == "float":
		f, _ := toFloat(v)
		binary.Write(w, binary.LittleEndian, float32(f))
	case u == "double":
		f, _ := toFloat(v)
		binary.Write(w, binary.LittleEndian, f)
	case u != "" && u != "object":
		size, signed, ok := intInfo(u)
		if !ok {
			return fmt.Errorf("%s: unknown underlying type %q", path, u)
		}
		i, ok := toInt(v)
		if !ok {
			return fmt.Errorf("%s: %T is not a number", path, v)
		}
		encodeInt(w, size, signed, opts, i)
	case typ == "string":
		s, _ := v.(string)
		c.putLength(w, opts, len(s))
		w.WriteString(s)
	case typ == "array":
		items, _ := n["items"].(node)
		list, _ := v.([]any)
		c.putLength(w, optionSet(n), len(list))
		for i, e := range list {
			if err := c.encode(w, items, e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case typ == "object" && n["properties"] != nil:
		obj, _ := v.(map[string]any)
		known := map[string]bool{}
		for _, f := range fields(n) {
			known[f.name] = true
			val := obj[f.name]
			if optionalField(n, f.name) {
				if _, absent := val.(absentVal); absent || val == nil {
					if val == nil {
						c.note("added optional %s (absent)", join(path, f.name))
					}
					w.WriteByte(0)
					continue
				}
				w.WriteByte(1)
			}
			if err := c.encode(w, f.node, val, join(path, f.name)); err != nil {
				return err
			}
		}
		var dropped []string
		for k := range obj {
			if !known[k] {
				dropped = append(dropped, k)
			}
		}
		sort.Strings(dropped)
		for _, k := range dropped {
			c.note("dropped %s", join(path, k))
		}
	case typ == "object" && n["additionalProperties"] != nil:
		entry, _ := n["additionalProperties"].(node)
		list, _ := v.([]any)
		c.putLength(w, optionSet(n), len(list))
		for i, e := range list {
			if err := c.encode(w, entry, e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case typ == "":
		raw, _ := v.(rawNBT)
		w.Write(raw)
	default:
		return fmt.Errorf("%s: unsupported schema node (type %q, underlying %q)", path, typ, u)
	}
	return nil
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func (c *codec) putLength(w *bytes.Buffer, opts map[string]bool, n int) {
	if opts["No size compression"] {
		binary.Write(w, binary.LittleEndian, uint32(n))
		return
	}
	putVaruint(w, uint64(n))
}

func encodeInt(w *bytes.Buffer, size int, signed bool, opts map[string]bool, i int64) {
	if opts["Compression"] {
		if signed {
			putVaruint(w, zigzag(i))
		} else {
			putVaruint(w, uint64(i))
		}
		return
	}
	buf := make([]byte, size)
	u := uint64(i)
	for k := 0; k < size; k++ {
		shift := uint(8 * k)
		if opts["Big Endian"] {
			buf[size-1-k] = byte(u >> shift)
		} else {
			buf[k] = byte(u >> shift)
		}
	}
	w.Write(buf)
}

func (c *codec) encodeOneOf(w *bytes.Buffer, n node, v any, path string) error {
	alts, _ := n["oneOf"].([]any)
	ov, ok := v.(oneOfVal)
	if !ok || int(ov.index) >= len(alts) {
		return fmt.Errorf("%s: no usable oneOf value", path)
	}
	putVaruint(w, ov.index)
	alt, _ := alts[ov.index].(node)
	if str(alt, "type") == "null" {
		return nil
	}
	return c.encode(w, alt, ov.value, path)
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		return int64(x), true
	case float64:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	}
	return 0, false
}

// zero builds the value written for a field the source version did not have: the schema's
// default where it names one, otherwise the empty value of the type.
func (c *codec) zero(n node) (any, error) {
	n, err := c.s.eff(n)
	if err != nil {
		return nil, err
	}
	u := str(n, "x-underlying-type")
	typ := str(n, "type")
	switch {
	case n["oneOf"] != nil:
		return oneOfVal{0, nil}, nil
	case u == "boolean" || typ == "boolean":
		d, _ := n["default"].(bool)
		return d, nil
	case u == "float" || u == "double":
		d, _ := n["default"].(float64)
		return d, nil
	case u != "" && u != "object":
		_, signed, _ := intInfo(u)
		return c.zeroInt(n, signed), nil
	case typ == "string":
		d, _ := n["default"].(string)
		return d, nil
	case typ == "array" || (typ == "object" && n["additionalProperties"] != nil):
		return []any{}, nil
	case typ == "object" && n["properties"] != nil:
		out := map[string]any{}
		for _, f := range fields(n) {
			if optionalField(n, f.name) {
				out[f.name] = absentVal{}
				continue
			}
			z, err := c.zero(f.node)
			if err != nil {
				return nil, err
			}
			out[f.name] = z
		}
		return out, nil
	case typ == "":
		return rawNBT{10, 0, 0}, nil
	}
	return nil, fmt.Errorf("no zero value for type %q", typ)
}

// zeroInt resolves an integer default, which may be given as a number or as the name of an enum
// value.
func (c *codec) zeroInt(n node, signed bool) any {
	idx := int64(0)
	switch d := n["default"].(type) {
	case float64:
		idx = int64(d)
	case string:
		if names, ok := n["enum"].([]any); ok {
			for i, name := range names {
				if name == d {
					idx = int64(i)
					if bin, ok := n["x-enum-binary-value"].([]any); ok && i < len(bin) {
						if f, ok := bin[i].(float64); ok {
							idx = int64(f)
						}
					}
				}
			}
		}
	}
	if signed {
		return idx
	}
	return uint64(idx)
}

func brief(v any) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 40 {
		s = s[:40] + "..."
	}
	return s
}
