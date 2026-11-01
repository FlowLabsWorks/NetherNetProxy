package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/FlowLabsWorks/NetherNetProxy/internal/schemacodec"
)

// tagSource serves the schema files of one tag to the codec.
type tagSource struct {
	d   *docs
	tag string
}

func (s tagSource) File(name string) ([]byte, error) { return s.d.file(s.tag, name) }

const (
	labelUnchanged = "templates-unchanged"
	labelChanged   = "templates-changed"
	labelUnknown   = "templates-unknown"
)

type templateResult struct {
	name   string
	status string // "unchanged", "changed" or "failed"
	detail string
	notes  []string
	old    []byte
	new    []byte
}

// templateCheck is the answer to: would the recorded packets look different on the wire under the
// new schemas?
type templateCheck struct {
	results []templateResult
	verdict string
	label   string
}

// checkTemplates decodes every recorded template with the baseline schemas and encodes it with the
// schemas of the new tag. Before that it proves the codec on the baseline: the recorded bytes must
// come out of the baseline schemas unchanged, otherwise the comparison would mean nothing. It
// returns nil when no template file is configured.
func (d *docs) checkTemplates(baseTag, newTag string) *templateCheck {
	if d.templates == "" {
		return nil
	}
	raw, err := os.ReadFile(d.templates)
	if err != nil {
		return nil
	}
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		return &templateCheck{label: labelUnknown, verdict: fmt.Sprintf("The template file %s is unreadable: %v.", d.templates, err)}
	}

	oldCodec := schemacodec.New(tagSource{d, baseTag})
	newCodec := schemacodec.New(tagSource{d, newTag})

	names := make([]string, 0, len(data))
	for n := range data {
		names = append(names, n)
	}
	sort.Strings(names)

	tc := &templateCheck{}
	var changed, failed int
	for _, name := range names {
		res := templateResult{name: name}
		b, err := hex.DecodeString(data[name])
		packet := strings.SplitN(name, "#", 2)[0]
		res.old = b
		switch {
		case err != nil:
			res.status, res.detail = "failed", "invalid hex in the template file"
		default:
			res.status, res.detail = d.convertOne(oldCodec, newCodec, packet, &res)
		}
		switch res.status {
		case "changed":
			changed++
		case "failed":
			failed++
		}
		tc.results = append(tc.results, res)
	}

	switch {
	case failed > 0:
		tc.label = labelUnknown
		tc.verdict = fmt.Sprintf("The check could not be completed for %d of %d templates (see below), so it says nothing about this change.", failed, len(names))
	case changed > 0:
		tc.label = labelChanged
		tc.verdict = fmt.Sprintf("%d of %d recorded templates would change on the wire. The candidate bytes below are derived from the schemas and have not been tried on a console.", changed, len(names))
	default:
		tc.label = labelUnchanged
		tc.verdict = fmt.Sprintf("All %d recorded templates encode to identical bytes under the new schemas, so the documented changes need no template update. Behaviour the schemas do not describe (new packets in the login sequence, new checks in the client) is not covered by this check.", len(names))
	}
	return tc
}

// convertOne fills res.new and res.notes and returns the status and a detail text.
func (d *docs) convertOne(oldCodec, newCodec *schemacodec.Codec, packet string, res *templateResult) (string, string) {
	v, err := oldCodec.Decode(packet, res.old)
	if err != nil {
		return "failed", "the recorded bytes do not fit the baseline schemas: " + err.Error()
	}
	again, _, err := oldCodec.Encode(packet, v)
	if err != nil || !bytes.Equal(again, res.old) {
		return "failed", "the baseline schemas do not reproduce the recorded bytes"
	}
	out, notes, err := newCodec.Encode(packet, v)
	if err != nil {
		return "failed", "cannot be written with the new schemas: " + err.Error()
	}
	res.new, res.notes = out, notes
	if bytes.Equal(out, res.old) {
		return "unchanged", ""
	}
	return "changed", fmt.Sprintf("%d -> %d bytes", len(res.old), len(out))
}

func (tc *templateCheck) markdown() string {
	var b strings.Builder
	b.WriteString("### Template check\n\n")
	b.WriteString(tc.verdict + "\n\n")
	if len(tc.results) == 0 {
		return b.String()
	}
	b.WriteString("| Template | Result |\n| --- | --- |\n")
	for _, r := range tc.results {
		result := r.status
		if r.status != "unchanged" {
			result = "**" + r.status + "**: " + r.detail
		}
		if len(r.notes) > 0 {
			result += " (" + strings.Join(r.notes, "; ") + ")"
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", r.name, result)
	}
	b.WriteString("\n")
	for _, r := range tc.results {
		if r.status != "changed" {
			continue
		}
		fmt.Fprintf(&b, "`%s`\n\n```text\nrecorded  %x\ncandidate %x\n```\n\n", r.name, r.old, r.new)
	}
	return b.String()
}
