package claude

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

const commandsDir = ".claude/commands"

// payloadRoots is walked in this fixed order so emit order is deterministic.
var payloadRoots = []string{skillsDir, commandsDir}

var payloadExtensions = map[string]bool{".sh": true, ".py": true, ".js": true}

const shebangPrefix = "#!"

type payloadCandidate struct {
	Path       string
	Ext        string
	Executable bool
}

// refSource holds raw bytes rather than parsed frontmatter, so correlation
// survives malformed YAML.
type refSource struct{ File, Text string }

type refIndex struct {
	skills   map[string]refSource
	commands []refSource
}

// executable treats an Info() error as not executable — an accepted
// under-report, pinned by TestExecutable_InfoErrorIsNotExecutable.
func executable(d fs.DirEntry) bool {
	info, err := d.Info()
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// bareDotfile reports whether p's base name is a leading dot and a stem with
// no further dot. path.Ext answers that shape with the whole base name, so
// such a name carries nothing to weigh against payloadExtensions. A name
// whose dot does separate an extension keeps that extension as its verdict
// and stays outside the sniff.
func bareDotfile(p string) bool {
	base := path.Base(p)
	return strings.HasPrefix(base, ".") && !strings.Contains(base[1:], ".")
}

// hasShebang inspects the leading shebangPrefix-length bytes, so a bundled
// binary is classified without being read whole.
func hasShebang(fsys fs.FS, p string) (bool, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, len(shebangPrefix))
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	return string(buf[:n]) == shebangPrefix, nil
}

// collectPayloads warns and continues on a mid-walk directory failure:
// aborting would drop the rest of the walk, including payloads in sibling
// subtrees not yet reached.
//
// Every read it makes stands behind a type check first.
func collectPayloads(fsys fs.FS, root string, idx *refIndex) ([]payloadCandidate, []adapter.Warning) {
	var candidates []payloadCandidate
	var warnings []adapter.Warning

	_ = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if d.IsDir() {
			return nil
		}

		// skillEntities resolves an in-tree symlinked SKILL.md and reads it,
		// so correlation has to see the same file rather than disagree with
		// it about whether a payload beside it is referenced.
		if path.Ext(p) == ".md" && fsguard.CheckEntryType(fsys, p, d.Type(), fsguard.CheckResolvedRegular) == nil {
			indexMarkdown(fsys, root, p, idx)
		}

		if !d.Type().IsRegular() {
			ext := strings.ToLower(path.Ext(p))
			if payloadExtensions[ext] || (d.Type()&fs.ModeSymlink != 0 && refusesLink(fsys, root, p, ext)) {
				warnings = append(warnings, adapter.Warning{File: p, Err: adapter.Unreadable(fmt.Errorf("skipping %q: not a regular file (%s)", p, d.Type()))})
			}
			return nil
		}

		ext := strings.ToLower(path.Ext(p))
		exec := executable(d)
		if !payloadExtensions[ext] && (!exec || ext == ".md") {
			// A host that cannot supply the +x bit leaves the shebang as the
			// last signal; TestPayloadEntitiesFIFOIsClassifiedWithoutOpening
			// pins the sniff below the regular-file gate.
			if ext != "" && !bareDotfile(p) {
				return nil
			}
			shebang, err := hasShebang(fsys, p)
			if err != nil {
				warnings = append(warnings, adapter.Warning{File: p, Err: adapter.Unreadable(err)})
				return nil
			}
			if !shebang {
				return nil
			}
		}

		candidates = append(candidates, payloadCandidate{Path: p, Ext: ext, Executable: exec})
		return nil
	})

	return candidates, warnings
}

func refusesLink(fsys fs.FS, root, p, ext string) bool {
	if (root == skillsDir && isSkillFile(p)) || (root == commandsDir && isMarkdownFile(p)) {
		return false
	}
	mode, err := fsguard.ResolvedMode(fsys, p)
	switch {
	case err != nil:
		return !errors.Is(err, fs.ErrNotExist)
	case mode.IsDir():
		return true
	case mode.IsRegular():
		return (mode.Perm()&0o111 != 0 && ext != ".md") || ext == "" || bareDotfile(p)
	default:
		return false
	}
}

func indexMarkdown(fsys fs.FS, root, p string, idx *refIndex) {
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return
	}
	src := refSource{File: p, Text: string(data)}

	switch root {
	case skillsDir:
		if path.Base(p) == skillFileName {
			idx.skills[path.Dir(p)] = src
		}
	case commandsDir:
		idx.commands = append(idx.commands, src)
	}
}

// resolve correlates within p's own root; cross-root correlation is an
// accepted under-report.
func (idx *refIndex) resolve(p string) (referenced, referencedBy string) {
	switch {
	case strings.HasPrefix(p, skillsDir+"/"):
		return idx.resolveSkill(p)
	case strings.HasPrefix(p, commandsDir+"/"):
		return idx.resolveCommand(p)
	default:
		return "", ""
	}
}

// resolveSkill uses the nearest ancestor's SKILL.md — the directory
// ${CLAUDE_SKILL_DIR} resolves to. A sibling reference.md is not indexed.
func (idx *refIndex) resolveSkill(p string) (string, string) {
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		if src, ok := idx.skills[dir]; ok {
			if mentions(src.Text, dir, p) {
				return "true", src.File
			}
			return "", ""
		}
		if dir == skillsDir || dir == "." {
			return "", ""
		}
	}
}

// resolveCommand takes the first mentioning file the walk indexed — a command
// file carries no per-file anchor to narrow the search — so which of several
// mentioning files gets named follows the FS's own ReadDir order.
func (idx *refIndex) resolveCommand(p string) (string, string) {
	for _, src := range idx.commands {
		if mentions(src.Text, ".", p) {
			return "true", src.File
		}
	}
	return "", ""
}

// mentions requires a dot in the base name it matches: widening to
// extension-less names would match bare words in incidental prose.
func mentions(text, ownerDir, payloadPath string) bool {
	text = expandDirVars(text, dirVars{Skill: ownerDir})

	if strings.Contains(text, payloadPath) {
		return true
	}

	if rel, ok := strings.CutPrefix(payloadPath, ownerDir+"/"); ok {
		if strings.Contains(text, rel) || strings.Contains(text, "./"+rel) {
			return true
		}
	}

	base := path.Base(payloadPath)
	return strings.Contains(base, ".") && strings.Contains(text, base)
}

type dirVars struct {
	Skill      string
	PluginRoot string
}

// expandDirVars leaves ${CLAUDE_PLUGIN_DATA} unsubstituted: it resolves
// outside the scanned tree, so expanding it would fabricate a path. Pinned by
// TestExpandDirVarsLeavesPluginDataLiteral.
func expandDirVars(text string, v dirVars) string {
	// The trailing-slash pair must precede the bare one wherever the
	// replacement collapses to the empty string: strings.NewReplacer resolves
	// an ambiguous same-position match in argument order, turning
	// "${CLAUDE_PROJECT_DIR}/x" into "x", not "./x".
	pairs := []string{
		"${CLAUDE_PROJECT_DIR}/", "",
		"${CLAUDE_PROJECT_DIR}", ".",
		"$CLAUDE_PROJECT_DIR/", "",
		"$CLAUDE_PROJECT_DIR", ".",
	}
	if v.Skill != "" {
		pairs = append(pairs,
			"${CLAUDE_SKILL_DIR}/", v.Skill+"/",
			"${CLAUDE_SKILL_DIR}", v.Skill,
			"$CLAUDE_SKILL_DIR/", v.Skill+"/",
			"$CLAUDE_SKILL_DIR", v.Skill,
		)
	}
	if v.PluginRoot != "" {
		pairs = append(pairs, pluginRootPairs(v.PluginRoot)...)
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

// pluginRootPairs collapses the trailing-slash form for a "." root, so
// "${CLAUDE_PLUGIN_ROOT}/bin/db" becomes "bin/db" rather than "./bin/db".
func pluginRootPairs(root string) []string {
	slash := root + "/"
	if root == "." {
		slash = ""
	}
	return []string{
		"${CLAUDE_PLUGIN_ROOT}/", slash,
		"${CLAUDE_PLUGIN_ROOT}", root,
		"$CLAUDE_PLUGIN_ROOT/", slash,
		"$CLAUDE_PLUGIN_ROOT", root,
	}
}

// payloadEntities resolves references after the walk rather than inside it,
// pinned by TestReferenceCorrelatorSurvivesEitherWalkOrder. Correlating
// inside the walk would let a payload's referenced verdict turn on whether
// its owning Markdown happened to be walked first, which an attacker-chosen
// filename can decide.
func payloadEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	idx := &refIndex{skills: map[string]refSource{}}

	perRoot := make([][]payloadCandidate, len(payloadRoots))
	var warnings []adapter.Warning
	for i, root := range payloadRoots {
		candidates, ws := collectPayloads(fsys, root, idx)
		warnings = append(warnings, ws...)
		perRoot[i] = candidates
	}

	var entities []ir.Entity
	for _, candidates := range perRoot {
		for _, c := range candidates {
			executableValue := ""
			if c.Executable {
				executableValue = "true"
			}
			referenced, referencedBy := idx.resolve(c.Path)
			payload, refused := limits.Of(fsys).Admit(c.Path, []ir.Entity{ir.BundledPayload{
				Path:         c.Path,
				Extension:    c.Ext,
				Executable:   executableValue,
				Referenced:   referenced,
				ReferencedBy: referencedBy,
				Location:     ir.Location{File: c.Path},
			}}, nil)
			entities = append(entities, payload...)
			warnings = append(warnings, refused...)
		}
	}

	return entities, warnings, nil
}
