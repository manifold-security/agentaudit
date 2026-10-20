package claude

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// inlineShellFromBody scans body for placeholder forms. firstLine anchors
// Location.Key's body[N] to the ORIGINAL file.
//
// Reporting a command Claude Code would not run costs the report its trust, so
// a fence run longer than the documented bang opener reads as a plain fence and
// its content stays unsurfaced; the edge is pinned by
// TestInlineShellFromBody_BangFenceOpenerRunBoundary.
func inlineShellFromBody(body []byte, firstLine int, shell, file string) []ir.Entity {
	var entities []ir.Entity
	lines := strings.Split(string(body), "\n")
	var inBang, inPlain bool

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimLeft(line, " \t")
		lineNo := firstLine + i

		switch {
		case inBang, inPlain:
			if strings.HasPrefix(trimmed, "```") {
				inBang, inPlain = false, false
				continue
			}
			if inBang {
				entities = append(entities, fencedEntitiesInLine(line, lineNo, shell, file)...)
			}
		case strings.HasPrefix(trimmed, "```"):
			if strings.HasPrefix(strings.TrimPrefix(trimmed, "```"), "!") {
				inBang = true
			} else {
				inPlain = true
			}
		default:
			entities = append(entities, inlineEntitiesInLine(line, lineNo, shell, file)...)
		}
	}
	return entities
}

func fencedEntitiesInLine(line string, lineNo int, shell, file string) []ir.Entity {
	cmd := strings.TrimSpace(line)
	if cmd == "" {
		return nil
	}
	return []ir.Entity{ir.InlineShell{
		Command:  cmd,
		Form:     "fenced",
		Shell:    shell,
		Location: ir.Location{File: file, Key: fmt.Sprintf("body[%d]", lineNo)},
	}}
}

// inlineEntitiesInLine honours "!" only at line start or directly after a
// space or tab, as Claude Code does, so a bang anywhere else would report a
// command that never runs; the eligible predecessors are pinned by
// TestInlineShellFromBody_InlineForm. An ineligible bang still advances the
// cursor, or a later placeholder on the same line is missed.
func inlineEntitiesInLine(line string, lineNo int, shell, file string) []ir.Entity {
	var entities []ir.Entity
	for i := 0; i < len(line); i++ {
		if line[i] != '!' {
			continue
		}
		if i > 0 && line[i-1] != ' ' && line[i-1] != '\t' {
			continue
		}
		if i+1 >= len(line) || line[i+1] != '`' {
			continue
		}
		j := strings.IndexByte(line[i+2:], '`')
		if j < 0 {
			continue
		}
		j += i + 2
		if cmd := strings.TrimSpace(line[i+2 : j]); cmd != "" {
			entities = append(entities, ir.InlineShell{
				Command:  cmd,
				Form:     "inline",
				Shell:    shell,
				Location: ir.Location{File: file, Key: fmt.Sprintf("body[%d]", lineNo)},
			})
		}
		i = j
	}
	return entities
}

// parseCommand treats a command file and a SKILL.md as one frontmatter
// schema, so a command's hooks declare what a skill's do, while a command
// emits no ir.Skill presence entity.
func parseCommand(data []byte, file string, room int) ([]ir.Entity, *adapter.Warning) {
	t := scanTarget(data, file, room)
	if !t.OK {
		return nil, t.Warning
	}

	faults := t.Faults
	hooks, err := hookGroupsFromNode(t.Frontmatter.Hooks, faults.room)
	faults.mark("hooks", err)

	entities := hookEntities(hooks, file)
	entities = append(entities, inlineShellFromBody(t.Body, t.FirstLine, t.Shell, file)...)

	return entities, firstWarning(t.Warning, faults, file)
}

var commandSource = markdownSource{matches: isMarkdownFile, parse: parseCommand}

func walkCommandDir(fsys fs.FS, dir string, check func(fs.FS, string) error) ([]ir.Entity, []adapter.Warning, error) {
	return walkMarkdownDir(fsys, dir, commandSource, check)
}

func commandEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return walkCommandDir(fsys, commandsDir, fsguard.CheckResolvedRegular)
}
