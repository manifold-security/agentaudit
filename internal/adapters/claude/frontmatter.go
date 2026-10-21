package claude

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const agentsDir = ".claude/agents"

const skillsDir = ".claude/skills"

const skillFileName = "SKILL.md"

const frontmatterFence = "---"

// subagentFrontmatter is the decoded shape of a .claude/agents/*.md file's
// frontmatter. A typed field would make decodeFrontmatter fail the WHOLE block
// over one key's shape, discarding the file's other entities with it; a
// yaml.Node defers each key to a resolver that confines and reports the loss.
type subagentFrontmatter struct {
	Name yaml.Node `yaml:"name"`
	// Tools resolves through toolsFromNode.
	Tools yaml.Node `yaml:"tools"`
	// PermissionMode is dual-mapped: a standalone entity for the rules to
	// match, and an ir.Subagent field carried for display.
	PermissionMode yaml.Node `yaml:"permissionMode"`
	// MCPServers resolves through mcpEntitiesFromNode.
	MCPServers yaml.Node `yaml:"mcpServers"`
	// Hooks resolves to the hookGroup shape settings.go decodes from JSON.
	Hooks yaml.Node `yaml:"hooks"`
}

// decodeFrontmatter charges a block whose aliases expand past room the nodes
// it counted, and refuses one expanding past maxAliasedNodes whatever the
// budget, before any resolver decodes them: yaml.v3 meters aliases per Decode
// call, and the resolvers decode one item at a time.
func decodeFrontmatter(block []byte, out any, room int) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(block, &doc); err != nil {
		return err
	}
	switch n := aliasedNodes(&doc, min(room, maxAliasedNodes)); {
	case n > room:
		return limits.Faults(n, fmt.Errorf("aliases expand past %d nodes", room))
	case n > maxAliasedNodes:
		return limits.Refusal(fmt.Sprintf("aliases expand past %d nodes; not scanned", maxAliasedNodes))
	}
	return doc.Decode(out)
}

const maxAliasedNodes = 1 << 20

// aliasedNodes walks on its own stack rather than recursing: chained aliases
// nest past the depth yaml.v3 parses to, and
// TestAliasedNodesWalksAChainedAliasWithinAOneMiBStack pins the walk.
func aliasedNodes(root *yaml.Node, limit int) int {
	type frame struct {
		n       *yaml.Node
		next    int
		aliased bool
	}
	count := 0
	expanding := map[*yaml.Node]bool{}
	var stack []frame
	enter := func(n *yaml.Node, aliased bool) {
		if aliased {
			count++
		}
		if n.Kind == yaml.AliasNode && n.Alias != nil {
			if expanding[n.Alias] {
				return
			}
			expanding[n.Alias] = true
		}
		stack = append(stack, frame{n: n, aliased: aliased})
	}
	for enter(root, false); len(stack) > 0 && count <= limit; {
		f := &stack[len(stack)-1]
		switch {
		case f.n.Kind == yaml.AliasNode && f.n.Alias != nil:
			if f.next == 0 {
				f.next = 1
				enter(f.n.Alias, true)
				continue
			}
			delete(expanding, f.n.Alias)
		case f.next < len(f.n.Content):
			f.next++
			enter(f.n.Content[f.next-1], f.aliased)
			continue
		}
		stack = stack[:len(stack)-1]
	}
	return count
}

// splitFrontmatter splits data's leading YAML frontmatter block from its
// body. A block found but not terminated is malformed and must warn.
func splitFrontmatter(data []byte) (block []byte, found bool, terminated bool) {
	// lines has at least one element, so lines[0] needs no length guard.
	lines := strings.Split(string(data), "\n")
	if strings.TrimRight(lines[0], "\r") != frontmatterFence {
		return nil, false, false
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == frontmatterFence {
			return []byte(strings.Join(lines[1:i], "\n")), true, true
		}
	}
	return nil, true, false
}

// frontmatterBody returns data's body — the ENTIRE file when there is no
// leading fence — and the 1-based line it begins on in the ORIGINAL file.
func frontmatterBody(data []byte) (body []byte, firstLine int) {
	lines := strings.Split(string(data), "\n")
	if strings.TrimRight(lines[0], "\r") != frontmatterFence {
		return data, 1
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == frontmatterFence {
			return []byte(strings.Join(lines[i+1:], "\n")), i + 2
		}
	}
	return nil, 0
}

func shellOf(raw string) string {
	if raw == "" {
		return "bash"
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// parseSubagent parses one .claude/agents/*.md file's bytes into its located
// ir entities. Entities and a warning can be returned together.
func parseSubagent(data []byte, file string, isPlugin bool, room int) ([]ir.Entity, *adapter.Warning) {
	block, found, terminated := splitFrontmatter(data)
	if !found {
		return nil, nil
	}
	if !terminated {
		return nil, &adapter.Warning{File: file, Err: errors.New("frontmatter: unterminated \"---\" fence")}
	}

	var fm subagentFrontmatter
	if err := decodeFrontmatter(block, &fm, room); err != nil {
		return nil, &adapter.Warning{File: file, Err: fmt.Errorf("frontmatter: %w", err)}
	}

	faults := keyFaults{room: room}
	entities := entitiesFromSubagent(fm, file, isPlugin, &faults)
	return entities, faults.warning(file)
}

const maxFaultText = 64 << 10

// keyFaults accumulates the keys a resolver could not decode, so one file
// reports ONE warning and the facade's per-source tally counts it once. Its
// error still charges the entity budget every fault, a nested resolver's too,
// but it keeps no text past room, where the budget refuses the file, nor once
// its text reaches maxFaultText bytes.
type keyFaults struct {
	faults []string
	count  int
	room   int
	text   int
}

func (k *keyFaults) full() bool {
	return k.count > k.room || k.text >= maxFaultText
}

func (k *keyFaults) write(fault string) {
	k.faults = append(k.faults, fault)
	k.text += len(fault)
}

// mark flattens yaml.v3's multi-line TypeError into the one line a warning
// occupies on stderr. A nil err records nothing, so callers need no guard.
func (k *keyFaults) mark(key string, err error) {
	if err == nil {
		return
	}
	k.count += limits.FaultCount(err)
	if k.full() {
		return
	}
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		err = errors.New(strings.Join(typeErr.Errors, "; "))
	}
	k.write(key + ": " + err.Error())
}

func (k *keyFaults) add(fault string) {
	k.count++
	if !k.full() {
		k.write(fault)
	}
}

func (k keyFaults) err() error {
	if k.count == 0 {
		return nil
	}
	return limits.Faults(k.count, errors.New(strings.Join(k.faults, "; ")))
}

// warning renders the accumulated faults as one per-source warning. It is not
// wrapped in adapter.Unreadable: the file WAS read, so the facade counts it as
// an unparsed source rather than an unreadable one — see isParseDiscard.
func (k keyFaults) warning(file string) *adapter.Warning {
	err := k.err()
	if err == nil {
		return nil
	}
	return &adapter.Warning{File: file, Err: fmt.Errorf("frontmatter: %w", err)}
}

// nullTag is the tag yaml.v3 gives a key written with no value ("hooks:").
const nullTag = "!!null"

// nodeAbsent reports whether node declares no value at all: a key missing
// from the block, or an explicit null. Neither loses anything, so neither is
// a fault — see TestParseSubagentFile_AbsentAndEmptyKeysStaySilent.
func nodeAbsent(node yaml.Node) bool {
	return node.Kind == 0 || node.Tag == nullTag
}

// yamlFormName names node's form in the config file's vocabulary, not Go's.
func yamlFormName(node yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		return "a single value"
	case yaml.SequenceNode:
		return "a list"
	case yaml.MappingNode:
		return "a mapping"
	default:
		return "an unrecognised form"
	}
}

// entitiesFromSubagent maps one decoded subagentFrontmatter into its located
// ir entities. isPlugin applies Claude Code's documented carve-out, verbatim:
// "For security reasons, hooks, mcpServers, and permissionMode are not
// supported for plugin-shipped agents." Re-emitting them would over-report a
// capability Claude Code itself refuses to grant, so an unreadable hooks or
// mcpServers raises no fault for a plugin; permissionMode still resolves for
// its ir.Subagent display value, so it still faults.
func entitiesFromSubagent(fm subagentFrontmatter, file string, isPlugin bool, faults *keyFaults) []ir.Entity {
	var entities []ir.Entity

	mode, err := scalarFromNode(fm.PermissionMode)
	faults.mark("permissionMode", err)

	if !isPlugin {
		hooks, err := hookGroupsFromNode(fm.Hooks, faults.room)
		faults.mark("hooks", err)
		entities = append(entities, hookEntities(hooks, file)...)

		servers, err := mcpEntitiesFromNode(fm.MCPServers, file, faults.room)
		faults.mark("mcpServers", err)
		entities = append(entities, servers...)

		if mode != "" {
			entities = append(entities, ir.PermissionMode{
				Mode:     mode,
				Source:   "permissionMode",
				Location: ir.Location{File: file, Key: "permissionMode"},
			})
		}
	}

	name, err := scalarFromNode(fm.Name)
	faults.mark("name", err)
	tools, terr := toolsFromNode(fm.Tools, faults.room)
	faults.mark("tools", terr)

	entities = append(entities, ir.Subagent{
		Name:           name,
		PermissionMode: mode,
		Tools:          tools,
		Location:       ir.Location{File: file, Key: "name"},
	})

	return entities
}

func mcpEntitiesFromNode(node yaml.Node, file string, room int) ([]ir.Entity, error) {
	node = resolveAlias(node)
	if nodeAbsent(node) {
		return nil, nil
	}
	switch node.Kind {
	case yaml.SequenceNode:
		return mcpEntitiesFromSequenceNode(node, file, room)
	case yaml.MappingNode:
		return mcpEntitiesFromMappingNode(node, file, room)
	default:
		return nil, fmt.Errorf("line %d: expected a list of server names or a mapping of server entries, found %s", node.Line, yamlFormName(node))
	}
}

// mcpEntitiesFromSequenceNode checks a scalar item's Tag rather than
// attempting a Decode: yaml.v3 also decodes a bool or int scalar into a Go
// string, so a Decode-based check would silently accept a non-string scalar
// as a server name — see
// TestParseSubagentFile_ListBadItemTypesWarnAloneSiblingsSurvive.
func mcpEntitiesFromSequenceNode(node yaml.Node, file string, room int) ([]ir.Entity, error) {
	faults := keyFaults{room: room}
	entities := make([]ir.Entity, 0, len(node.Content))
	for i, itemPtr := range node.Content {
		item := resolveAlias(*itemPtr)
		entry := fmt.Sprintf("entry %d", i)
		switch {
		case item.Kind == yaml.ScalarNode && item.Tag == "!!str":
			entities = append(entities, ir.MCPServer{
				Name:     item.Value,
				Location: ir.Location{File: file, Key: fmt.Sprintf("mcpServers[%d]", i)},
			})
		case item.Kind == yaml.MappingNode && len(item.Content) == 2:
			var name string
			if err := item.Content[0].Decode(&name); err != nil {
				faults.mark(entry, err)
				continue
			}
			keyPrefix := fmt.Sprintf("mcpServers[%d]", i)
			entities = append(entities, mcpEntryEntities(name, *item.Content[1], file, keyPrefix, entry+": ", &faults)...)
		default:
			faults.mark(entry, fmt.Errorf(
				"line %d: expected a server name or a single-key map, found %s", item.Line, yamlFormName(item)))
		}
	}
	return entities, faults.err()
}

// mcpEntitiesFromMappingNode walks the mapping's pairs directly: Content is a
// flat [key0, val0, ...] slice in source-document order, already deterministic
// unlike Go map iteration, and per-entry decoding confines a bad entry.
func mcpEntitiesFromMappingNode(node yaml.Node, file string, room int) ([]ir.Entity, error) {
	faults := keyFaults{room: room}
	entities := make([]ir.Entity, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		var name string
		if err := node.Content[i].Decode(&name); err != nil {
			faults.mark(fmt.Sprintf("entry %d", i/2), err)
			continue
		}
		entities = append(entities, mcpEntryEntities(name, *node.Content[i+1], file, "mcpServers", "", &faults)...)
	}
	return entities, faults.err()
}

func mcpEntryEntities(name string, val yaml.Node, file, keyPrefix, label string, faults *keyFaults) []ir.Entity {
	val = resolveAlias(val)

	if val.Kind == yaml.ScalarNode {
		return []ir.Entity{
			ir.MCPServer{Name: name, Location: ir.Location{File: file, Key: keyPrefix + "." + name}},
		}
	}

	var entry mcpjson.Entry
	if err := val.Decode(&entry); err != nil {
		faults.mark(label+name, err)
		return nil
	}
	mcpEnts, mcpWarnings := entitiesFromMCPMap(map[string]mcpjson.Entry{name: entry}, file, keyPrefix)
	for _, w := range mcpWarnings {
		faults.add(label + strings.TrimPrefix(w.Err.Error(), keyPrefix+"."))
	}
	return mcpEnts
}

// toolsFromNode reads tools in either spelling the schema and real agent
// files use. A shape or item it cannot read costs only that value.
func toolsFromNode(node yaml.Node, room int) ([]string, error) {
	node = resolveAlias(node)
	if nodeAbsent(node) {
		return nil, nil
	}
	switch node.Kind {
	case yaml.SequenceNode:
		faults := keyFaults{room: room}
		out := make([]string, 0, len(node.Content))
		for i, item := range node.Content {
			var tool string
			if err := item.Decode(&tool); err != nil {
				faults.mark(fmt.Sprintf("[%d]", i), err)
				continue
			}
			if tool = strings.TrimSpace(tool); tool != "" {
				out = append(out, tool)
			}
		}
		if len(out) == 0 {
			return nil, faults.err()
		}
		return out, faults.err()
	case yaml.ScalarNode:
		var csv string
		if err := node.Decode(&csv); err != nil {
			return nil, err
		}
		return splitCSV(csv), nil
	default:
		return nil, fmt.Errorf("line %d: expected a string or a list of tool names, found %s", node.Line, yamlFormName(node))
	}
}

// resolveAlias yields the node an anchor reference names, so a Kind check
// sees the referenced shape rather than yaml.v3's separate alias Kind — an
// anchored value declares a real capability, and refusing it would drop it.
func resolveAlias(node yaml.Node) yaml.Node {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return *node.Alias
	}
	return node
}

// scalarFromNode reads a frontmatter key the schema declares as a string.
// A non-scalar yields "" AND a fault, so it stays distinguishable from the
// absent key that yields "" alone. A bool or int scalar renders as a
// string, so the Kind check refuses neither — see TestScalarFromNode.
func scalarFromNode(node yaml.Node) (string, error) {
	node = resolveAlias(node)
	if nodeAbsent(node) {
		return "", nil
	}
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("line %d: expected a string, found %s", node.Line, yamlFormName(node))
	}
	var s string
	if err := node.Decode(&s); err != nil {
		return "", err
	}
	return s, nil
}

// hookGroupsFromNode decodes a hooks node PER GROUP rather than as one
// map[string][]hookGroup, so a group whose matcher is unreadable cannot blank
// every well-formed sibling. A group's decode error does not skip the group:
// yaml.v3 reports a type error only after populating the fields that did
// decode, so the group still carries its commands, and appending it either
// way keeps its index matching its position in the source document — the
// index hookEntities reports in Location.Key.
func hookGroupsFromNode(node yaml.Node, room int) (map[string][]hookGroup, error) {
	node = resolveAlias(node)
	if nodeAbsent(node) {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: expected a mapping of event names, found %s", node.Line, yamlFormName(node))
	}
	faults := keyFaults{room: room}
	hooks := make(map[string][]hookGroup, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		var event string
		if err := node.Content[i].Decode(&event); err != nil {
			faults.mark(fmt.Sprintf("entry %d", i/2), err)
			continue
		}
		seq := resolveAlias(*node.Content[i+1])
		if nodeAbsent(seq) {
			continue
		}
		if seq.Kind != yaml.SequenceNode {
			faults.mark(event, fmt.Errorf("line %d: expected a list of hook groups, found %s", seq.Line, yamlFormName(seq)))
			continue
		}
		if len(seq.Content) == 0 {
			continue
		}
		groups := make([]hookGroup, 0, len(seq.Content))
		for gi, item := range seq.Content {
			var group hookGroup
			faults.mark(fmt.Sprintf("%s[%d]", event, gi), item.Decode(&group))
			groups = append(groups, group)
		}
		hooks[event] = groups
	}
	if len(hooks) == 0 {
		return nil, faults.err()
	}
	return hooks, faults.err()
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

type markdownSource struct {
	matches func(p string) bool
	parse   func(data []byte, file string, room int) ([]ir.Entity, *adapter.Warning)
	// namesLinks stays unset where collectPayloads walks the same tree and
	// names the link itself.
	namesLinks bool
}

func isMarkdownFile(p string) bool { return path.Ext(p) == ".md" }

// isSkillFile matches the base name rather than directory membership, which
// keeps a reference.md sibling in a skill directory from reading as a skill.
func isSkillFile(p string) bool { return path.Base(p) == skillFileName }

var skillSource = markdownSource{matches: isSkillFile, parse: parseSkill}

// walkMarkdownDir parses every file src selects independently, so one
// malformed file warns and the walk continues; a missing dir is not an error.
// check decides what a surface accepts beyond a plain regular file.
func walkMarkdownDir(fsys fs.FS, dir string, src markdownSource, check func(fs.FS, string) error) ([]ir.Entity, []adapter.Warning, error) {
	var entities []ir.Entity
	var warnings []adapter.Warning

	walkErr := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			// Returning would abort the walk, not just this entry.
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !src.matches(p) {
			if src.namesLinks && d.Type()&fs.ModeSymlink != 0 && fsguard.LinkMayHideEntries(fsys, p) {
				warnings = append(warnings, adapter.Warning{File: p, Err: fsguard.IrregularRefusal(p, d.Type())})
			}
			return nil
		}
		if cerr := fsguard.CheckEntryType(fsys, p, d.Type(), check); cerr != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: cerr})
			return nil
		}

		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: rerr})
			return nil
		}

		es, w := src.parse(data, p, limits.Of(fsys).Room())
		var ws []adapter.Warning
		if w != nil {
			ws = append(ws, *w)
		}
		es, ws = limits.Of(fsys).Admit(p, es, ws)
		entities = append(entities, es...)
		warnings = append(warnings, ws...)
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}

	return entities, warnings, nil
}

// pluginShippedAgent and projectAgent name walkAgentDir's isPlugin flag at its
// call sites; the distinction is a security control — see
// entitiesFromSubagent.
const (
	pluginShippedAgent = true
	projectAgent       = false
)

func walkAgentDir(fsys fs.FS, dir string, isPlugin bool) ([]ir.Entity, []adapter.Warning, error) {
	return walkMarkdownDir(fsys, dir, markdownSource{
		matches: isMarkdownFile,
		parse: func(data []byte, file string, room int) ([]ir.Entity, *adapter.Warning) {
			return parseSubagent(data, file, isPlugin, room)
		},
		namesLinks: true,
	}, fsguard.CheckRegular)
}

func agentEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return walkAgentDir(fsys, agentsDir, projectAgent)
}

// skillFrontmatter is the decoded shape of a SKILL.md frontmatter block, with
// Shell selecting which shell runs inline !`cmd`/```! blocks.
type skillFrontmatter struct {
	Name  yaml.Node `yaml:"name"`
	Shell yaml.Node `yaml:"shell"`
	Hooks yaml.Node `yaml:"hooks"`
}

// scannableBody is scanTarget's result. OK is false ONLY for a
// found-but-unterminated fence, the one accepted under-report.
type scannableBody struct {
	Body        []byte
	FirstLine   int
	Shell       string
	Frontmatter skillFrontmatter
	// HasFrontmatter is true only when a terminated fence was found AND its
	// YAML parsed cleanly; it is what gates entitiesFromSkill.
	HasFrontmatter bool
	Warning        *adapter.Warning
	OK             bool
	// Faults carries the keys scanTarget resolved itself and could not read,
	// for the caller to merge with its own before warning once.
	Faults keyFaults
}

// scanTarget resolves data's inline-shell-scannable body independently of
// frontmatter validity: a malformed or absent frontmatter must never hide a
// body command. Only an unterminated fence leaves no body boundary to scan.
func scanTarget(data []byte, file string, room int) scannableBody {
	block, found, terminated := splitFrontmatter(data)

	if found && !terminated {
		return scannableBody{
			Warning: &adapter.Warning{File: file, Err: errors.New("frontmatter: unterminated \"---\" fence")},
			OK:      false,
		}
	}

	body, firstLine := frontmatterBody(data)
	t := scannableBody{Body: body, FirstLine: firstLine, Shell: "bash", OK: true, Faults: keyFaults{room: room}}

	if found {
		if err := decodeFrontmatter(block, &t.Frontmatter, room); err != nil {
			t.Frontmatter = skillFrontmatter{}
			t.Warning = &adapter.Warning{File: file, Err: fmt.Errorf("frontmatter: %w", err)}
		} else {
			t.HasFrontmatter = true
			shell, err := scalarFromNode(t.Frontmatter.Shell)
			t.Faults.mark("shell", err)
			t.Shell = shellOf(shell)
		}
	}
	return t
}

// parseSkill parses one SKILL.md file's bytes into its located ir entities.
// A warning may accompany entities from the same file.
func parseSkill(data []byte, file string, room int) ([]ir.Entity, *adapter.Warning) {
	t := scanTarget(data, file, room)
	if !t.OK {
		return nil, t.Warning
	}

	faults := t.Faults
	var entities []ir.Entity
	if t.HasFrontmatter {
		entities = entitiesFromSkill(t.Frontmatter, file, &faults)
	}
	entities = append(entities, inlineShellFromBody(t.Body, t.FirstLine, t.Shell, file)...)

	return entities, firstWarning(t.Warning, faults, file)
}

// firstWarning prefers scanTarget's block-level warning over the key-level
// faults: a block that failed to parse carries no keys to report.
func firstWarning(blockWarning *adapter.Warning, faults keyFaults, file string) *adapter.Warning {
	if blockWarning != nil {
		return blockWarning
	}
	return faults.warning(file)
}

// entitiesFromSkill maps one decoded skillFrontmatter into its ir entities.
// The presence entity is emitted whether or not a hook was declared.
func entitiesFromSkill(fm skillFrontmatter, file string, faults *keyFaults) []ir.Entity {
	var entities []ir.Entity

	hooks, err := hookGroupsFromNode(fm.Hooks, faults.room)
	faults.mark("hooks", err)
	entities = append(entities, hookEntities(hooks, file)...)

	name, nerr := scalarFromNode(fm.Name)
	faults.mark("name", nerr)
	entities = append(entities, ir.Skill{
		Name:     name,
		Location: ir.Location{File: file, Key: "name"},
	})

	return entities
}

func walkSkillDir(fsys fs.FS, dir string, check func(fs.FS, string) error) ([]ir.Entity, []adapter.Warning, error) {
	return walkMarkdownDir(fsys, dir, skillSource, check)
}

func skillEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return walkSkillDir(fsys, skillsDir, fsguard.CheckResolvedRegular)
}
