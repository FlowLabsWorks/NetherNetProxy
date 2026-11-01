package schemacodec

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testSchemas exercises every construct the codec supports. Extra is not listed in "required", so
// it is written with a presence byte.
func testSchemas() MapSource {
	return MapSource{
		"TestPacket.json": `{"$ref": "./TestPayload.json"}`,
		"TestPayload.json": `{
  "type": "object",
  "properties": {
    "Count":  {"type": "integer", "x-underlying-type": "uint32", "x-serialization-options": ["Compression"], "x-ordinal-index": 0},
    "Delta":  {"type": "integer", "x-underlying-type": "int32",  "x-serialization-options": ["Compression"], "x-ordinal-index": 1},
    "Status": {"type": "integer", "x-underlying-type": "int32",  "x-serialization-options": ["Big Endian"],  "x-ordinal-index": 2},
    "Name":   {"type": "string", "x-ordinal-index": 3},
    "Flags":  {"type": "array", "items": {"type": "boolean", "x-underlying-type": "boolean"}, "x-ordinal-index": 4},
    "Pos":    {"$ref": "./Vec.json", "x-ordinal-index": 5},
    "Level":  {"$ref": "./Level.json", "x-serialization-options": ["Compression", "Enum-as-Value"], "x-ordinal-index": 6},
    "Tag":    {"x-ordinal-index": 7},
    "Extra":  {"type": "object", "properties": {"On": {"type": "boolean", "x-underlying-type": "boolean", "x-ordinal-index": 0}}, "x-ordinal-index": 8}
  },
  "required": ["Count", "Delta", "Status", "Name", "Flags", "Pos", "Level", "Tag"]
}`,
		"Vec.json": `{"type": "object", "properties": {
  "X": {"type": "number", "x-underlying-type": "float", "x-ordinal-index": 0},
  "Y": {"type": "number", "x-underlying-type": "float", "x-ordinal-index": 1}}}`,
		"Level.json": `{"type": "string", "enum": ["Low", "High"], "x-underlying-type": "int32"}`,
	}
}

// 300 -> ac 02; -3 -> zigzag 5; 2 big endian; "ab"; [true,false]; 1.0 and 2.0; level 1 -> zigzag 2;
// an empty compound tag; Extra absent.
const testPayload = "ac02 05 00000002 026162 02 0100 0000803f 00000040 02 0a0000 00"

func TestRoundTrip(t *testing.T) {
	c := New(testSchemas())
	for name, hexs := range map[string]string{
		"extra absent":  testPayload,
		"extra present": strings.TrimSuffix(testPayload, "00") + "01 01",
	} {
		t.Run(name, func(t *testing.T) {
			b := fromHex(t, hexs)
			v, err := c.Decode("TestPacket", b)
			if err != nil {
				t.Fatal(err)
			}
			obj := v.(map[string]any)
			if obj["Count"] != uint64(300) || obj["Delta"] != int64(-3) || obj["Status"] != int64(2) || obj["Name"] != "ab" {
				t.Errorf("decoded %v", obj)
			}
			out, notes, err := c.Encode("TestPacket", v)
			if err != nil || len(notes) != 0 {
				t.Fatalf("encode: %v notes=%v", err, notes)
			}
			if !bytes.Equal(out, b) {
				t.Errorf("round trip changed the bytes:\n got  %x\n want %x", out, b)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	c := New(testSchemas())
	b := fromHex(t, testPayload)
	if _, err := c.Decode("TestPacket", append(b, 0xff)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Errorf("trailing bytes: %v", err)
	}
	if _, err := c.Decode("TestPacket", b[:len(b)-4]); err == nil {
		t.Error("a truncated payload must fail")
	}
	if _, err := c.Decode("NoSuchPacket", b); err == nil {
		t.Error("a missing schema must fail")
	}
}

func TestConvertAddsAndDrops(t *testing.T) {
	old := New(testSchemas())
	v, err := old.Decode("TestPacket", fromHex(t, testPayload))
	if err != nil {
		t.Fatal(err)
	}

	// The new version drops Delta and Status, adds Mode (default "High" = binary value 20) and a
	// Gain with a numeric default, and makes Extra mandatory.
	next := testSchemas()
	next["TestPayload.json"] = `{
  "type": "object",
  "properties": {
    "Count": {"type": "integer", "x-underlying-type": "uint32", "x-serialization-options": ["Compression"], "x-ordinal-index": 0},
    "Name":  {"type": "string", "x-ordinal-index": 1},
    "Mode":  {"type": "string", "enum": ["Low", "High"], "x-enum-binary-value": [10, 20], "default": "High", "x-underlying-type": "uint8", "x-ordinal-index": 2},
    "Gain":  {"type": "integer", "x-underlying-type": "uint16", "default": 7, "x-ordinal-index": 3},
    "Extra": {"type": "object", "properties": {"On": {"type": "boolean", "x-underlying-type": "boolean", "x-ordinal-index": 0}}, "x-ordinal-index": 4}
  },
  "required": ["Count", "Name", "Mode", "Gain", "Extra"]
}`
	out, notes, err := New(next).Encode("TestPacket", v)
	if err != nil {
		t.Fatal(err)
	}
	// Count ac02, Name 026162, Mode 14, Gain 0700 (little endian), Extra.On false 00
	if want := fromHex(t, "ac02 026162 14 0700 00"); !bytes.Equal(out, want) {
		t.Errorf("got %x want %x", out, want)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"added Mode = 20", "added Gain = 7", "dropped Delta", "dropped Status", "dropped Flags", "added Extra = map[On:false]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
}

func TestOneOfAndMaps(t *testing.T) {
	src := MapSource{
		"RulePacket.json": `{"type": "object", "properties": {
  "Value": {"oneOf": [{"type": "null"}, {"type": "boolean", "x-underlying-type": "boolean"}, {"type": "integer", "x-underlying-type": "int32"}], "x-ordinal-index": 0},
  "Names": {"type": "object", "additionalProperties": {"type": "string"}, "x-ordinal-index": 1}}}`,
	}
	c := New(src)
	// Value: alternative 2 (int32, little endian fixed) = 5; Names: two entries.
	b := fromHex(t, "02 05000000 02 0161 0162")
	v, err := c.Decode("RulePacket", b)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := c.Encode("RulePacket", v)
	if err != nil || !bytes.Equal(out, b) {
		t.Errorf("round trip: %x err=%v", out, err)
	}
	if _, err := c.Decode("RulePacket", fromHex(t, "09")); err == nil {
		t.Error("an out-of-range oneOf index must fail")
	}
}

func TestNBTVariants(t *testing.T) {
	src := MapSource{"TagPacket.json": `{"type": "object", "properties": {"Tag": {"x-ordinal-index": 0}}}`}
	c := New(src)
	// A root compound with a list of two ints (1 and -1 as zigzag varints, length 2 as zigzag 4), a
	// string "x" and a byte array [9] (length 1 as zigzag 2), then the end tag.
	b := fromHex(t, "0a00  09 016c 03 04 02 01  08 0173 0178  07 0162 02 09  00")
	v, err := c.Decode("TagPacket", b)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := c.Encode("TagPacket", v)
	if err != nil || !bytes.Equal(out, b) {
		t.Errorf("round trip: %x err=%v", out, err)
	}
}
