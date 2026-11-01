package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRepo serves a release list and raw schema files for a few tags, mimicking the GitHub API
// and raw.githubusercontent.com layout.
type fakeRepo struct {
	order []string                     // newest first
	files map[string]map[string]string // tag -> file -> content
}

func (f *fakeRepo) docs(t *testing.T) *docs {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/repos/o/r/releases", func(w http.ResponseWriter, r *http.Request) {
		var rs []release
		for _, tag := range f.order {
			rs = append(rs, release{Tag: tag})
		}
		json.NewEncoder(w).Encode(rs)
	})
	mux.HandleFunc("/raw/o/r/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/raw/o/r/")
		tag, name, ok := strings.Cut(rest, "/json/")
		content, found := f.files[tag][name]
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, content)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return newDocs("o/r", srv.URL+"/api", srv.URL+"/raw", "")
}

// schemaSet builds a complete set of schema files for one tag: every watched packet refers to
// Shared.json, StartGamePacket additionally to its own payload file.
func schemaSet(minecraft string, protocol int, shared, startPayload string) map[string]string {
	files := map[string]string{
		// minimum and maximum are pinned to the protocol version, like in RequestNetworkSettings.
		"Shared.json": fmt.Sprintf("{\n  \"x-minecraft-version\": %q,\n  \"x-protocol-version\": %d,\n  \"minimum\": %d.0,\n  \"maximum\": %d.0,\n%s\n}\n",
			minecraft, protocol, protocol, protocol, shared),
		"StartGamePacketPayload.json": fmt.Sprintf("{\n  \"x-protocol-version\": %d,\n  \"properties\": {\n%s\n  }\n}\n",
			protocol, startPayload),
	}
	for _, w := range watched {
		ref := "./Shared.json"
		if w.name == "StartGamePacket" {
			ref = "./StartGamePacketPayload.json"
		}
		files[w.name+".json"] = fmt.Sprintf("{\n  \"x-minecraft-version\": %q,\n  \"x-protocol-version\": %d,\n  \"$ref\": %q,\n  \"other\": {\"$ref\": \"./Shared.json\"}\n}\n",
			minecraft, protocol, ref)
	}
	return files
}

func TestHashIgnoresVersionLines(t *testing.T) {
	f := &fakeRepo{files: map[string]map[string]string{
		"v1": schemaSet("1.0", 100, `"a": 1`, `"x": 1`),
		"v2": schemaSet("1.1", 101, `"a": 1`, `"x": 1`),
		"v3": schemaSet("1.1", 101, `"a": 2`, `"x": 1`),
	}}
	d := f.docs(t)
	s1, err := d.snapshot("v1")
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := d.snapshot("v2")
	s3, _ := d.snapshot("v3")
	if s1.Protocol != 100 || s2.Protocol != 101 {
		t.Fatalf("protocols = %d, %d", s1.Protocol, s2.Protocol)
	}
	for name := range s1.Packets {
		if s1.Packets[name] != s2.Packets[name] {
			t.Errorf("%s: hash changed although only version lines differ", name)
		}
	}
	if s1.Packets["TransferPacket"] == s3.Packets["TransferPacket"] {
		t.Error("a change in a shared type must change the hash of the packets using it")
	}
	if s1.Packets["StartGamePacket"] != s2.Packets["StartGamePacket"] {
		t.Error("StartGamePacket changed unexpectedly")
	}
}

func TestCheckReportsChange(t *testing.T) {
	f := &fakeRepo{files: map[string]map[string]string{
		"v1":         schemaSet("1.0", 100, `"a": 1`, `"x": 1`),
		"v2":         schemaSet("1.1", 101, `"a": 1`, `"x": 1`),
		"v3-preview": schemaSet("1.2", 102, `"a": 1`, "\"x\": 1,\n    \"managed\": true"),
		"v4":         schemaSet("1.3", 103, `"a": 1`, "\"x\": 1,\n    \"managed\": true"),
	}}
	d := f.docs(t)
	base, err := d.snapshot("v1")
	if err != nil {
		t.Fatal(err)
	}

	findings, err := check(d, base, []string{"v1", "v2"})
	if err != nil || len(findings) != 0 {
		t.Fatalf("unchanged docs: findings=%v err=%v", findings, err)
	}

	findings, err = check(d, base, []string{"v3-preview", "v4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("the same change in two tags must be reported once, got %d", len(findings))
	}
	got := findings[0]
	if !strings.Contains(got.Title, "StartGame") || !strings.Contains(got.Title, got.Key) || len(got.Key) != 12 {
		t.Errorf("title = %q key = %q", got.Title, got.Key)
	}
	for _, want := range []string{"v3-preview", "preview", "`StartGamePacket`", "StartGamePacketPayload.json", `+     "managed": true`, "```diff"} {
		if !strings.Contains(got.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, got.Body)
		}
	}
	if strings.Contains(got.Body, "`TransferPacket`") {
		t.Errorf("an unaffected packet is listed:\n%s", got.Body)
	}

	again, _ := check(d, base, []string{"v4"})
	if len(again) != 1 || again[0].Key != got.Key {
		t.Error("the key must not depend on the tag")
	}
}

func TestCheckMissingSchemaAndBaselineGaps(t *testing.T) {
	v2 := schemaSet("1.1", 101, `"a": 1`, `"x": 1`)
	delete(v2, "TransferPacket.json")
	f := &fakeRepo{files: map[string]map[string]string{
		"v1": schemaSet("1.0", 100, `"a": 1`, `"x": 1`),
		"v2": v2,
	}}
	d := f.docs(t)
	base, _ := d.snapshot("v1")

	findings, err := check(d, base, []string{"v2"})
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Body, "schema no longer found") {
		t.Fatalf("findings=%v err=%v", findings, err)
	}

	delete(base.Packets, "StartGamePacket")
	if _, err := check(d, base, []string{"v2"}); err == nil || !strings.Contains(err.Error(), "StartGamePacket") {
		t.Errorf("a baseline without an entry must be an error, got %v", err)
	}
}

func TestPickTags(t *testing.T) {
	// Publication order as Mojang did it: the stable 1.26.61 came after the 1.26.70 preview.
	rs := []release{{Tag: "v1.26.61"}, {Tag: "v1.26.70-preview.22"}, {Tag: "v1.26.60"}, {Tag: "v1.26.70-preview.21"}, {Tag: "v1.26.60-preview.30"}}
	pick := func(rs []release, base string) string {
		t.Helper()
		got, err := pickTags(rs, base)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(got, ",")
	}
	if got := pick(rs, ""); got != "v1.26.70-preview.22,v1.26.61" {
		t.Errorf("no baseline: got %s", got)
	}
	if got := pick(rs, "v1.26.60"); got != "v1.26.70-preview.22,v1.26.61" {
		t.Errorf("baseline 1.26.60: got %s", got)
	}
	// Only versions above the baseline count, whatever the publication order.
	if got := pick(rs, "v1.26.61"); got != "v1.26.70-preview.22" {
		t.Errorf("baseline 1.26.61: got %s", got)
	}
	if got := pick(rs, "v1.26.70-preview.22"); got != "" {
		t.Errorf("baseline is the newest: got %s", got)
	}
	if got := pick(rs, "v1.26.60-preview.30"); got != "v1.26.70-preview.22,v1.26.61" {
		t.Errorf("baseline is a preview: got %s", got)
	}
	// A preview sorts before its stable release.
	if got := pick([]release{{Tag: "v1.2.0-preview.9"}, {Tag: "v1.2.0"}}, "v1.2.0-preview.9"); got != "v1.2.0" {
		t.Errorf("stable after preview: got %s", got)
	}
	if got := pick([]release{{Tag: "v9.9.9", Draft: true}, {Tag: "v1.0.0"}}, ""); got != "v1.0.0" {
		t.Errorf("drafts must be skipped: got %s", got)
	}
	if _, err := pickTags([]release{{Tag: "release-2026"}}, ""); err == nil {
		t.Error("an unknown tag scheme must be an error")
	}
}

func TestUnifiedLines(t *testing.T) {
	a := strings.Split("1\n2\n3\n4\n5\n6\n7\n8\n9\n10", "\n")
	b := strings.Split("1\n2\n3\n4\nX\n6\n7\n8\n9\n10", "\n")
	got, ok := unifiedLines(a, b)
	if !ok {
		t.Fatal("diff refused")
	}
	if want := "  3|  4|- 5|+ X|  6|  7"; strings.Join(got, "|") != want {
		t.Errorf("got %q want %q", strings.Join(got, "|"), want)
	}
	if got, _ := unifiedLines(nil, []string{"a"}); strings.Join(got, "|") != "+ a" {
		t.Errorf("new file diff = %v", got)
	}
}

func TestRunUpdateAndCheck(t *testing.T) {
	f := &fakeRepo{
		order: []string{"v1.1.0-preview.1", "v1.0.0"},
		files: map[string]map[string]string{
			"v1.0.0":           schemaSet("1.0", 100, `"a": 1`, `"x": 1`),
			"v1.1.0-preview.1": schemaSet("1.1", 101, `"a": 1`, `"x": 2`),
		},
	}
	d := f.docs(t)
	dir := t.TempDir()
	basePath := filepath.Join(dir, "docs", "baseline.json")
	outPath := filepath.Join(dir, "findings.json")

	if err := run(d, basePath, "", "v1.0.0", ""); err != nil {
		t.Fatal(err)
	}
	// With no tags given, the newest release (the preview) is checked.
	if err := run(d, basePath, outPath, "", ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var findings []finding
	if err := json.Unmarshal(raw, &findings); err != nil || len(findings) != 1 || findings[0].Tag != "v1.1.0-preview.1" {
		t.Fatalf("findings = %s (%v)", raw, err)
	}

	// Taking over the new state makes the next run quiet; the file is still valid JSON ("[]").
	if err := run(d, basePath, "", "v1.1.0-preview.1", ""); err != nil {
		t.Fatal(err)
	}
	if err := run(d, basePath, outPath, "", ""); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(outPath)
	if strings.TrimSpace(string(raw)) != "[]" {
		t.Errorf("expected no findings, got %s", raw)
	}
}

func TestTemplateCheck(t *testing.T) {
	chunk := func(files map[string]string, props, required string) map[string]string {
		files["ChunkRadiusUpdatedPacket.json"] = `{"$ref": "./ChunkPayload.json"}`
		files["ChunkPayload.json"] = `{"type": "object", "properties": {
  "Chunk Radius": {"type": "integer", "x-underlying-type": "int32", "x-serialization-options": ["Compression"], "x-ordinal-index": 0}` + props +
			`}, "required": ["Chunk Radius"` + required + `]}`
		return files
	}
	f := &fakeRepo{files: map[string]map[string]string{
		"vBase": chunk(schemaSet("1.0", 100, `"a": 1`, `"x": 1`), "", ""),
		// A new field with a default: the recorded bytes would grow by one.
		"vNew": chunk(schemaSet("1.1", 101, `"a": 2`, `"x": 1`),
			`, "Flag": {"type": "boolean", "x-underlying-type": "boolean", "default": true, "x-ordinal-index": 1}`, `, "Flag"`),
		// Something else changed, the chunk radius schema did not.
		"vSame": chunk(schemaSet("1.2", 102, `"a": 3`, `"x": 1`), "", ""),
		// A construct the codec cannot write.
		"vBroken": chunk(schemaSet("1.3", 103, `"a": 4`, `"x": 1`),
			`, "Odd": {"type": "weird", "x-ordinal-index": 1}`, `, "Odd"`),
	}}
	d := f.docs(t)
	d.templates = filepath.Join(t.TempDir(), "templates.json")
	// 0x20 is the zigzag varint for a chunk radius of 16.
	if err := os.WriteFile(d.templates, []byte(`{"ChunkRadiusUpdatedPacket": "20"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := d.snapshot("vBase")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		tag, label string
		body       []string
	}{
		{"vNew", labelChanged, []string{"### Template check", "**changed**: 1 -> 2 bytes", "added Flag = true", "recorded  20", "candidate 2001"}},
		{"vSame", labelUnchanged, []string{"### Template check", "identical bytes", "| `ChunkRadiusUpdatedPacket` | unchanged |"}},
		{"vBroken", labelUnknown, []string{"### Template check", "could not be completed", "**failed**"}},
	}
	for _, c := range cases {
		t.Run(c.tag, func(t *testing.T) {
			findings, err := check(d, base, []string{c.tag})
			if err != nil || len(findings) != 1 {
				t.Fatalf("findings=%v err=%v", findings, err)
			}
			got := findings[0]
			if len(got.Labels) != 2 || got.Labels[0] != "protocol-change" || got.Labels[1] != c.label {
				t.Errorf("labels = %v, want protocol-change and %s", got.Labels, c.label)
			}
			for _, want := range c.body {
				if !strings.Contains(got.Body, want) {
					t.Errorf("body lacks %q:\n%s", want, got.Body)
				}
			}
		})
	}

	// A baseline that does not reproduce the recorded bytes must not produce a verdict.
	if err := os.WriteFile(d.templates, []byte(`{"ChunkRadiusUpdatedPacket": "2000"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := check(d, base, []string{"vSame"})
	if err != nil || len(findings) != 1 || findings[0].Labels[1] != labelUnknown {
		t.Fatalf("a template that does not fit the baseline must give %s: %v %v", labelUnknown, findings, err)
	}
}
