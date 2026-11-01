// Command protocolwatch compares the Bedrock protocol schemas that Mojang publishes in
// github.com/Mojang/bedrock-protocol-docs with a committed baseline and reports changes to the
// packets NetherNetProxy depends on. The "Protocol watch" workflow runs it on a schedule and opens
// an issue for every new change.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// watched lists the packets the proxy replays to the console, builds itself or reads from the
// console (see bedrock.go). A change to the schema of any of them, including the shared types it
// refers to, can mean the recorded templates no longer fit.
var watched = []struct{ name, role string }{
	{"RequestNetworkSettingsPacket", "read from the console"},
	{"LoginPacket", "read from the console"},
	{"ResourcePackClientResponsePacket", "read from the console"},
	{"ClientCacheStatusPacket", "read from the console"},
	{"RequestChunkRadiusPacket", "read from the console"},
	{"SetLocalPlayerAsInitializedPacket", "read from the console"},
	{"NetworkSettingsPacket", "replayed to the console"},
	{"PlayStatusPacket", "replayed to the console"},
	{"ResourcePacksInfoPacket", "replayed to the console"},
	{"ResourcePackStackPacket", "replayed to the console"},
	{"JigsawStructureDataPacket", "replayed to the console (packet 313)"},
	{"VoxelShapesPacket", "replayed to the console (packet 337)"},
	{"StartGamePacket", "replayed to the console"},
	{"ItemRegistryPacket", "replayed to the console"},
	{"ChunkRadiusUpdatedPacket", "replayed to the console"},
	{"CreativeContentPacket", "replayed to the console (packet 145)"},
	{"TransferPacket", "built by the proxy"},
}

const (
	missing      = "missing"
	maxDiffCells = 4_000_000
	maxDiffLines = 60
)

var (
	errNotFound = errors.New("not found")
	tagPattern  = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-preview\.(\d+))?$`)
	refPattern  = regexp.MustCompile(`"\$ref"\s*:\s*"\./([^"#]+)`)
	protoRegexp = regexp.MustCompile(`"x-protocol-version"\s*:\s*(\d+)`)
)

// baseline is the committed reference: one hash per watched packet, computed over the packet's
// schema and every schema it refers to.
type baseline struct {
	Source   string            `json:"source"`
	Tag      string            `json:"tag"`
	Protocol int               `json:"protocol"`
	Packets  map[string]string `json:"packets"`
}

// finding is one change worth an issue. Key identifies the change itself, independent of the tag
// it was seen in, so the workflow can tell whether it has been reported already.
type finding struct {
	Title  string   `json:"title"`
	Key    string   `json:"key"`
	Tag    string   `json:"tag"`
	Labels []string `json:"labels"`
	Body   string   `json:"body"`
}

type docs struct {
	http  *http.Client
	repo  string
	api   string
	raw   string
	token string
	cache map[string][]byte

	// templates is the file with the recorded packets for the template check; empty skips it.
	templates string
}

func newDocs(repo, api, raw, token string) *docs {
	return &docs{
		http:  &http.Client{Timeout: 30 * time.Second},
		repo:  repo,
		api:   strings.TrimRight(api, "/"),
		raw:   strings.TrimRight(raw, "/"),
		token: token,
		cache: map[string][]byte{},
	}
}

func main() {
	var (
		repo     = flag.String("repo", "Mojang/bedrock-protocol-docs", "GitHub repository that publishes the schemas")
		apiURL   = flag.String("api-url", "https://api.github.com", "GitHub API base URL")
		rawURL   = flag.String("raw-url", "https://raw.githubusercontent.com", "base URL for raw files")
		basePath = flag.String("baseline", "docs/protocol-baseline.json", "baseline file")
		out      = flag.String("out", "", "write the findings as JSON to this file")
		update   = flag.String("update", "", "write a new baseline from this tag and exit")
		tags     = flag.String("tags", "", "comma separated tags to check instead of the newest release and preview")
		tplPath  = flag.String("templates", "tools/protocolwatch/templates.json", "recorded packets for the template check (empty to skip)")
	)
	flag.Parse()

	d := newDocs(*repo, *apiURL, *rawURL, os.Getenv("GITHUB_TOKEN"))
	d.templates = *tplPath
	if err := run(d, *basePath, *out, *update, *tags); err != nil {
		fmt.Fprintln(os.Stderr, "protocolwatch:", err)
		os.Exit(1)
	}
}

func run(d *docs, basePath, out, update, tags string) error {
	if update != "" {
		snap, err := d.snapshot(update)
		if err != nil {
			return err
		}
		for _, w := range watched {
			if snap.Packets[w.name] == missing {
				return fmt.Errorf("%s has no schema for %s", update, w.name)
			}
		}
		if err := writeJSON(basePath, snap); err != nil {
			return err
		}
		fmt.Printf("baseline written: %s (protocol %d, %d packets)\n", snap.Tag, snap.Protocol, len(snap.Packets))
		return nil
	}

	raw, err := os.ReadFile(basePath)
	if err != nil {
		return fmt.Errorf("reading the baseline: %w", err)
	}
	var base baseline
	if err := json.Unmarshal(raw, &base); err != nil {
		return fmt.Errorf("%s: %w", basePath, err)
	}

	candidates := splitTags(tags)
	if len(candidates) == 0 {
		releases, err := d.releases()
		if err != nil {
			return err
		}
		if candidates, err = pickTags(releases, base.Tag); err != nil {
			return err
		}
	}
	if len(candidates) == 0 {
		fmt.Printf("baseline %s (protocol %d) is the newest release\n", base.Tag, base.Protocol)
	} else {
		fmt.Printf("baseline %s (protocol %d); checking %s\n", base.Tag, base.Protocol, strings.Join(candidates, ", "))
	}

	findings, err := check(d, &base, candidates)
	if err != nil {
		return err
	}
	if out != "" {
		if err := writeJSON(out, findings); err != nil {
			return err
		}
	}
	return nil
}

func splitTags(s string) []string {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

type release struct {
	Tag   string `json:"tag_name"`
	Draft bool   `json:"draft"`
}

// tagVersion orders release tags such as v1.26.61 and v1.26.70-preview.22. The publication order
// is no help: Mojang published v1.26.61 after the preview of the next version, 1.26.70.
type tagVersion struct {
	nums [3]int
	pre  int // preview number; math.MaxInt for a stable release, so it sorts after its previews
}

func parseTag(tag string) (tagVersion, bool) {
	m := tagPattern.FindStringSubmatch(tag)
	if m == nil {
		return tagVersion{}, false
	}
	v := tagVersion{pre: math.MaxInt}
	for i := range v.nums {
		v.nums[i], _ = strconv.Atoi(m[i+1])
	}
	if m[4] != "" {
		v.pre, _ = strconv.Atoi(m[4])
	}
	return v, true
}

func (a tagVersion) less(b tagVersion) bool {
	for i := range a.nums {
		if a.nums[i] != b.nums[i] {
			return a.nums[i] < b.nums[i]
		}
	}
	return a.pre < b.pre
}

// pickTags returns the highest version among the releases and previews and the highest stable
// release, as far as they are newer than baseTag: an older tag differing from the baseline is no
// news. Often both are the same tag. It is an error if no tag follows the expected scheme, so a
// renamed scheme cannot silence the watch.
func pickTags(releases []release, baseTag string) ([]string, error) {
	base, baseOK := parseTag(baseTag)
	var newest, newestStable string
	var nv, ns tagVersion
	parsed := 0
	for _, r := range releases {
		v, ok := parseTag(r.Tag)
		if r.Draft || !ok {
			continue
		}
		parsed++
		if r.Tag == baseTag || (baseOK && !base.less(v)) {
			continue
		}
		if newest == "" || nv.less(v) {
			newest, nv = r.Tag, v
		}
		if v.pre == math.MaxInt && (newestStable == "" || ns.less(v)) {
			newestStable, ns = r.Tag, v
		}
	}
	if parsed == 0 {
		return nil, errors.New("no release tag follows the expected scheme (v1.2.3 or v1.2.3-preview.4)")
	}
	var tags []string
	if newest != "" {
		tags = append(tags, newest)
	}
	if newestStable != "" && newestStable != newest {
		tags = append(tags, newestStable)
	}
	return tags, nil
}

func (d *docs) releases() ([]release, error) {
	b, err := d.get(d.api+"/repos/"+d.repo+"/releases?per_page=30", true)
	if err != nil {
		return nil, err
	}
	var rs []release
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("release list: %w", err)
	}
	if len(rs) == 0 {
		return nil, errors.New("the repository lists no releases")
	}
	return rs, nil
}

func (d *docs) get(u string, auth bool) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "NetherNetProxy-protocolwatch")
		if auth && d.token != "" {
			req.Header.Set("Authorization", "Bearer "+d.token)
		}
		resp, err := d.http.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s: %w", u, errNotFound)
		}
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("%s: %s", u, resp.Status)
			continue
		}
		return body, nil
	}
	return nil, last
}

func (d *docs) file(tag, name string) ([]byte, error) {
	key := tag + "/" + name
	if b, ok := d.cache[key]; ok {
		return b, nil
	}
	b, err := d.get(d.raw+"/"+d.repo+"/"+url.PathEscape(tag)+"/json/"+url.PathEscape(name), false)
	if err != nil {
		return nil, err
	}
	d.cache[key] = b
	return b, nil
}

// closure returns the schema file of a packet and, transitively, every file it refers to.
func (d *docs) closure(tag, packet string) (map[string][]byte, error) {
	files := map[string][]byte{}
	queue := []string{packet + ".json"}
	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, ok := files[name]; ok {
			continue
		}
		b, err := d.file(tag, name)
		if err != nil {
			return nil, err
		}
		files[name] = b
		for _, m := range refPattern.FindAllSubmatch(b, -1) {
			ref, err := url.PathUnescape(string(m[1]))
			if err != nil {
				return nil, fmt.Errorf("%s: bad $ref %q", name, m[1])
			}
			queue = append(queue, ref)
		}
	}
	return files, nil
}

// normalize drops the lines that change with every release and unifies line endings, so only real
// schema changes alter a hash. That is the game and protocol version stamp and a "minimum" or
// "maximum" pinned to the protocol version (RequestNetworkSettings carries the one it accepts).
func normalize(b []byte) string {
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	var pinned *regexp.Regexp
	if m := protoRegexp.FindStringSubmatch(text); m != nil {
		pinned = regexp.MustCompile(`^\s*"(minimum|maximum)"\s*:\s*` + m[1] + `(\.0)?,?\s*$`)
	}
	lines := strings.Split(text, "\n")
	kept := lines[:0]
	for _, l := range lines {
		if strings.Contains(l, `"x-minecraft-version"`) || strings.Contains(l, `"x-protocol-version"`) {
			continue
		}
		if pinned != nil && pinned.MatchString(l) {
			continue
		}
		kept = append(kept, l)
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n")
}

func hashClosure(c map[string][]byte) string {
	names := make([]string, 0, len(c))
	for n := range c {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\n%s\n", n, normalize(c[n]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func protocolOf(b []byte) int {
	m := protoRegexp.FindSubmatch(b)
	if m == nil {
		return 0
	}
	var n int
	fmt.Sscanf(string(m[1]), "%d", &n)
	return n
}

// snapshot hashes every watched packet of a tag. A packet whose schema is gone gets the hash
// "missing", which counts as a change.
func (d *docs) snapshot(tag string) (*baseline, error) {
	s := &baseline{Source: d.repo, Tag: tag, Packets: map[string]string{}}
	for _, w := range watched {
		c, err := d.closure(tag, w.name)
		switch {
		case errors.Is(err, errNotFound):
			s.Packets[w.name] = missing
		case err != nil:
			return nil, err
		default:
			s.Packets[w.name] = hashClosure(c)
			if s.Protocol == 0 {
				s.Protocol = protocolOf(c[w.name+".json"])
			}
		}
	}
	if s.Protocol == 0 {
		return nil, fmt.Errorf("no protocol version found in %s", tag)
	}
	return s, nil
}

func check(d *docs, base *baseline, tags []string) ([]finding, error) {
	for _, w := range watched {
		if base.Packets[w.name] == "" {
			return nil, fmt.Errorf("the baseline has no entry for %s; regenerate it with -update %s", w.name, base.Tag)
		}
	}
	findings := []finding{}
	seen := map[string]bool{}
	for _, tag := range tags {
		if tag == base.Tag {
			continue
		}
		snap, err := d.snapshot(tag)
		if err != nil {
			return nil, err
		}
		var changed []string
		for _, w := range watched {
			if snap.Packets[w.name] != base.Packets[w.name] {
				changed = append(changed, w.name)
			}
		}
		if len(changed) == 0 {
			fmt.Printf("%s (protocol %d): no change to the packets the proxy uses\n", tag, snap.Protocol)
			continue
		}
		f := d.describe(base, snap, changed)
		fmt.Printf("%s (protocol %d): CHANGED %s [%s] %s\n", tag, snap.Protocol, strings.Join(changed, ", "), f.Key, strings.Join(f.Labels[1:], ","))
		if !seen[f.Key] {
			seen[f.Key] = true
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func roleOf(packet string) string {
	for _, w := range watched {
		if w.name == packet {
			return w.role
		}
	}
	return ""
}

func (d *docs) describe(base, snap *baseline, changed []string) finding {
	parts := make([]string, len(changed))
	for i, n := range changed {
		parts[i] = n + "=" + snap.Packets[n]
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	key := hex.EncodeToString(sum[:])[:12]

	short := make([]string, 0, len(changed))
	for _, n := range changed {
		short = append(short, strings.TrimSuffix(n, "Packet"))
	}
	if len(short) > 3 {
		short = append(short[:3], fmt.Sprintf("+%d more", len(changed)-3))
	}
	title := fmt.Sprintf("Bedrock protocol docs changed: %s (%s)", strings.Join(short, ", "), key)

	kind := "release"
	if strings.Contains(snap.Tag, "-preview") {
		kind = "preview"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Mojang's published Bedrock protocol schemas for **%s** (%s, protocol %d) differ from the baseline (`%s`, protocol %d) in packets NetherNetProxy depends on.\n\n",
		snap.Tag, kind, snap.Protocol, base.Tag, base.Protocol)
	b.WriteString("| Packet | Used for |\n| --- | --- |\n")
	for _, n := range changed {
		role := roleOf(n)
		if snap.Packets[n] == missing {
			role += "; schema no longer found"
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", n, role)
	}

	b.WriteString("\n### Schema changes\n\n")
	b.WriteString(d.fileDiffs(base.Tag, snap.Tag, changed))

	labels := []string{"protocol-change"}
	if tc := d.checkTemplates(base.Tag, snap.Tag); tc != nil {
		b.WriteString(tc.markdown())
		labels = append(labels, tc.label)
	}

	fmt.Fprintf(&b, `### What to do

1. Check whether the game version behind `+"`%s`"+` has reached your console. Preview tags are betas; only a stable release matters for most players.
2. Once the console is updated, join through the proxy. If that works, nothing is broken: refresh the baseline with `+"`go run ./tools/protocolwatch -update %s`"+`, commit it and close this issue.
3. If the join hangs, or the template check lists candidate bytes, update the templates (`+"`cmd/nethernet-proxy/bedrock.go`"+` and `+"`tools/protocolwatch/templates.json`"+`) as described in `+"`docs/UPDATING.md`"+`, then refresh the baseline.

Change key: `+"`%s`"+`. Opened by the "Protocol watch" workflow.
`, snap.Tag, snap.Tag, key)

	return finding{Title: title, Key: key, Tag: snap.Tag, Labels: labels, Body: b.String()}
}

type fileChange struct {
	packets []string
	old     *string
	new     *string
}

// fileDiffs lists every schema file that differs between two tags within the closures of the
// changed packets, once per file, as a diff.
func (d *docs) fileDiffs(oldTag, newTag string, changed []string) string {
	files := map[string]*fileChange{}
	for _, packet := range changed {
		oldC, oldErr := d.closure(oldTag, packet)
		newC, newErr := d.closure(newTag, packet)
		if oldErr != nil && newErr != nil {
			continue
		}
		names := map[string]bool{}
		for n := range oldC {
			names[n] = true
		}
		for n := range newC {
			names[n] = true
		}
		for n := range names {
			var o, nw *string
			if b, ok := oldC[n]; ok {
				s := normalize(b)
				o = &s
			}
			if b, ok := newC[n]; ok {
				s := normalize(b)
				nw = &s
			}
			if o != nil && nw != nil && *o == *nw {
				continue
			}
			fc := files[n]
			if fc == nil {
				fc = &fileChange{old: o, new: nw}
				files[n] = fc
			}
			fc.packets = append(fc.packets, packet)
		}
	}
	if len(files) == 0 {
		return "The schema files could not be compared (a tag may be unreachable); see the hashes in the workflow log.\n\n"
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		fc := files[n]
		state := "changed"
		switch {
		case fc.old == nil:
			state = "new file"
		case fc.new == nil:
			state = "removed"
		}
		fmt.Fprintf(&b, "**`%s`** (%s; used by %s)\n\n```diff\n", n, state, strings.Join(fc.packets, ", "))
		var a, c []string
		if fc.old != nil {
			a = strings.Split(*fc.old, "\n")
		}
		if fc.new != nil {
			c = strings.Split(*fc.new, "\n")
		}
		lines, ok := unifiedLines(a, c)
		if !ok {
			b.WriteString("(file too large to diff)\n")
		}
		for i, l := range lines {
			if i == maxDiffLines {
				fmt.Fprintf(&b, "... (%d more lines)\n", len(lines)-maxDiffLines)
				break
			}
			b.WriteString(l + "\n")
		}
		b.WriteString("```\n\n")
	}
	return b.String()
}

// unifiedLines returns the changed lines of a diff with two lines of context. It reports false
// when the inputs are too large for the quadratic algorithm.
func unifiedLines(a, b []string) ([]string, bool) {
	n, m := len(a), len(b)
	if n*m > maxDiffCells {
		return nil, false
	}
	t := make([]int32, (n+1)*(m+1))
	at := func(i, j int) *int32 { return &t[i*(m+1)+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				*at(i, j) = *at(i+1, j+1) + 1
			case *at(i+1, j) >= *at(i, j+1):
				*at(i, j) = *at(i+1, j)
			default:
				*at(i, j) = *at(i, j+1)
			}
		}
	}

	type op struct {
		tag  byte
		text string
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{' ', a[i]})
			i++
			j++
		case *at(i+1, j) >= *at(i, j+1):
			ops = append(ops, op{'-', a[i]})
			i++
		default:
			ops = append(ops, op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', b[j]})
	}

	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.tag == ' ' {
			continue
		}
		for c := max(0, k-2); c <= min(len(ops)-1, k+2); c++ {
			keep[c] = true
		}
	}
	var out []string
	skipped := false
	for k, o := range ops {
		if !keep[k] {
			skipped = true
			continue
		}
		if skipped && len(out) > 0 {
			out = append(out, "...")
		}
		skipped = false
		out = append(out, string(o.tag)+" "+o.text)
	}
	return out, true
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
