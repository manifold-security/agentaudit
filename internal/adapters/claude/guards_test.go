package claude

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// parseResult groups a surface's return values into the one value a channel
// can carry.
type parseResult struct {
	entities []ir.Entity
	warnings []adapter.Warning
	err      error
}

type parseSurface func(fs.FS) ([]ir.Entity, []adapter.Warning, error)

func parseAll(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) { return New().Parse(fsys) }

func fifo(data []byte) *fstest.MapFile {
	return &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: data}
}

const (
	helperSettingsJSON = `{"apiKeyHelper":"/tmp/helper.sh"}`
	oneServerJSON      = `{"mcpServers":{"x":{"command":"npx"}}}`
)

// bounded runs parse against fsys and fails as a deadline rather than hanging
// the suite when a guard opens what it was meant to classify.
func bounded(t *testing.T, parse parseSurface, fsys fs.FS) parseResult {
	t.Helper()

	done := make(chan parseResult, 1)
	go func() {
		entities, warnings, err := parse(fsys)
		done <- parseResult{entities, warnings, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("parse error = %v, want nil", got.err)
		}
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("the surface never returned; it opened the entry instead of reading its type bits")
		return parseResult{}
	}
}

func wantSoleRefusal(t *testing.T, got parseResult, file string) {
	t.Helper()

	if len(got.entities) != 0 {
		t.Fatalf("entities = %+v, want none: the entry is refused, never read", got.entities)
	}
	if len(got.warnings) != 1 || got.warnings[0].File != file {
		t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, file)
	}
	if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
		t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
	}
	if !strings.Contains(got.warnings[0].Err.Error(), "not a regular file") {
		t.Errorf("warning = %q, want it to name the refusal reason", got.warnings[0].Err)
	}
}

// Each source below reaches its verdict from the entry's type bits alone.
func TestGuardedSourcesRefuseAFIFOWithoutOpening(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		fsys  fs.FS
		parse parseSurface
	}{
		{
			name:  "settings.json",
			file:  ".claude/settings.json",
			fsys:  blockingWalkFS{m: fstest.MapFS{".claude/settings.json": fifo([]byte(helperSettingsJSON))}},
			parse: parseAll,
		},
		{
			name:  "settings.local.json",
			file:  ".claude/settings.local.json",
			fsys:  blockingWalkFS{m: fstest.MapFS{".claude/settings.local.json": fifo([]byte(helperSettingsJSON))}},
			parse: parseAll,
		},
		{
			name:  "the project .mcp.json",
			file:  mcpFileName,
			fsys:  blockingWalkFS{m: fstest.MapFS{mcpFileName: fifo([]byte(oneServerJSON))}},
			parse: mcpEntities,
		},
		{
			name:  "a skill file",
			file:  ".claude/skills/demo/SKILL.md",
			fsys:  blockingWalkFS{m: fstest.MapFS{".claude/skills/demo/SKILL.md": fifo(skillBody("demo", "skill-inline.sh").Data)}},
			parse: skillEntities,
		},
		{
			name:  "a command file",
			file:  ".claude/commands/deploy.md",
			fsys:  blockingWalkFS{m: fstest.MapFS{".claude/commands/deploy.md": fifo(inlineBody("command-inline.sh").Data)}},
			parse: commandEntities,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantSoleRefusal(t, bounded(t, tt.parse, tt.fsys), tt.file)
		})
	}
}

// The payload walk reads a .md to correlate references, so it must classify
// the entry before that read. An irregular entry outside the payload
// extensions stays silent, so the proof here is that the call returns at all.
func TestPayloadEntitiesMarkdownFIFOIsClassifiedWithoutOpening(t *testing.T) {
	tests := []struct {
		name string
		m    fstest.MapFS
	}{
		{
			name: "the entry is the pipe",
			m: fstest.MapFS{
				".claude/skills/demo/SKILL.md": fifo(skillBody("demo", "skill-inline.sh").Data),
			},
		},
		{
			name: "the entry links to the pipe",
			m: fstest.MapFS{
				".claude/skills/demo/SKILL.md": symlink("../../../target"),
				"target":                       fifo(skillBody("demo", "skill-inline.sh").Data),
			},
		},
		{
			name: "the entry links nowhere",
			m: fstest.MapFS{
				".claude/skills/demo/SKILL.md": symlink("../../../nothing-here.md"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bounded(t, payloadEntities, blockingWalkFS{m: tt.m})
			if len(got.entities) != 0 || len(got.warnings) != 0 {
				t.Fatalf("payloadEntities() = (%+v, %+v), want neither for an irregular entry outside the payload extensions", got.entities, got.warnings)
			}
		})
	}
}

// collectPayloads and skillEntities must agree about the same file. A project
// SKILL.md reached through an in-tree symlink is read for its capabilities, so
// it also has to supply the correlation that marks a payload beside it as
// referenced; a payload the report cannot attribute to its owner is the
// weaker finding.
func TestPayloadEntitiesCorrelateThroughAnInTreeSymlinkedSkillFile(t *testing.T) {
	const payload = ".claude/skills/demo/run.sh"
	fsys := fstest.MapFS{
		".claude/skills/demo/SKILL.md": symlink("../../../shared/SKILL.md"),
		payload:                        &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		"shared/SKILL.md":              skillBody("demo", "run.sh"),
	}

	entities, warnings, err := payloadEntities(fsys)
	if err != nil {
		t.Fatalf("payloadEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("payloadEntities() warnings = %+v, want none", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("payloadEntities() = %+v, want the one payload beside the skill", entities)
	}

	got, ok := entities[0].(ir.BundledPayload)
	if !ok {
		t.Fatalf("entity %T is not ir.BundledPayload", entities[0])
	}
	if got.Path != payload || got.Referenced != "true" || got.ReferencedBy != ".claude/skills/demo/SKILL.md" {
		t.Fatalf("payload = %+v, want %q referenced by the symlinked SKILL.md", got, payload)
	}
}

// Resolution reaches the target through Stat alone: an Open on the way there
// blocks on the pipe the link names, which is the hang resolution invites.
func TestGuardedSourcesRefuseASymlinkToAFIFOWithoutOpening(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		fsys  fs.FS
		parse parseSurface
	}{
		{
			name: "settings.json",
			file: ".claude/settings.json",
			fsys: blockingWalkFS{m: fstest.MapFS{
				".claude/settings.json": symlink("../target"),
				"target":                fifo([]byte(helperSettingsJSON)),
			}},
			parse: parseAll,
		},
		{
			name: "the project .mcp.json",
			file: mcpFileName,
			fsys: blockingOpenFS{m: fstest.MapFS{
				mcpFileName: symlink("target"),
				"target":    fifo([]byte(oneServerJSON)),
			}},
			parse: mcpEntities,
		},
		{
			name: "a skill file",
			file: ".claude/skills/demo/SKILL.md",
			fsys: blockingWalkFS{m: fstest.MapFS{
				".claude/skills/demo/SKILL.md": symlink("../../../target"),
				"target":                       fifo(skillBody("demo", "skill-inline.sh").Data),
			}},
			parse: skillEntities,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantSoleRefusal(t, bounded(t, tt.parse, tt.fsys), tt.file)
		})
	}
}

// Admitting a link because it resolved at all would read whatever it names, so
// the resolved target's own type decides. The mode in the message stays the
// link's, never the target's.
func TestGuardedSourcesRefuseASymlinkToADirectory(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		fsys  fs.FS
		parse parseSurface
	}{
		{
			name: "the project .mcp.json",
			file: mcpFileName,
			fsys: fstest.MapFS{
				mcpFileName:    symlink("target"),
				"target/inner": &fstest.MapFile{Data: []byte(oneServerJSON)},
			},
			parse: mcpEntities,
		},
		{
			name: "a skill file",
			file: ".claude/skills/demo/SKILL.md",
			fsys: fstest.MapFS{
				".claude/skills/demo/SKILL.md": symlink("../../../target"),
				"target/inner":                 skillBody("demo", "skill-inline.sh"),
			},
			parse: skillEntities,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bounded(t, tt.parse, tt.fsys)
			wantSoleRefusal(t, got, tt.file)

			want := fmt.Sprintf("refusing to read %q: not a regular file (L---------)", tt.file)
			if msg := got.warnings[0].Err.Error(); msg != want {
				t.Fatalf("warning = %q, want %q", msg, want)
			}
		})
	}
}

// A dotfile manager symlinking a config into the tree is ordinary, so a link
// resolving to a regular file is read. Refusing every link instead would
// silently un-scan that layout and report the project as clean.
func TestGuardedSourcesReadAnInTreeSymlinkedConfig(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": symlink("../real-settings.json"),
		"real-settings.json":    &fstest.MapFile{Data: []byte(helperSettingsJSON)},
		mcpFileName:             symlink("real-mcp.json"),
		"real-mcp.json":         &fstest.MapFile{Data: []byte(oneServerJSON)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	var helper, server bool
	for _, e := range entities {
		switch v := e.(type) {
		case ir.CredentialHelper:
			helper = v.Command == "/tmp/helper.sh"
		case ir.MCPServer:
			server = v.Name == "x"
		}
	}
	if !helper || !server {
		t.Fatalf("Parse() entities = %+v, want the symlinked settings helper and the symlinked .mcp.json server", entities)
	}
}

// An absent source is not a degraded read. The guard answers ahead of
// fs.ReadFile, so its own not-exist error has to reach the same silent
// branch — on an FS that reports link modes and on one that does not.
func TestGuardedSourcesStaySilentWhenTheFileIsAbsent(t *testing.T) {
	tests := []struct {
		name string
		fsys fs.FS
	}{
		{
			name: "nothing in the tree",
			fsys: fstest.MapFS{"unrelated.txt": &fstest.MapFile{Data: []byte("x")}},
		},
		{
			name: "the config directory exists without the file",
			fsys: fstest.MapFS{".claude/unrelated.txt": &fstest.MapFile{Data: []byte("x")}},
		},
		{
			name: "an FS without fs.ReadLinkFS, where absence is read off a listing",
			fsys: blockingWalkFS{m: fstest.MapFS{".claude/unrelated.txt": &fstest.MapFile{Data: []byte("x")}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bounded(t, parseAll, tt.fsys)
			if len(got.entities) != 0 || len(got.warnings) != 0 {
				t.Fatalf("Parse() = (%+v, %+v), want silence: an absent source is not a degraded read", got.entities, got.warnings)
			}
		})
	}
}

// A regular or irregular entry is settled from the walk's own listing; only a
// symlink costs another.
func TestWalkMarkdownDirRelistsForASymlinkOnly(t *testing.T) {
	tests := []struct {
		name         string
		m            fstest.MapFS
		wantCalls    int
		wantRead     []string
		wantWarnings int
	}{
		{
			name: "regular entries cost the walk's own listing",
			m: fstest.MapFS{
				".claude/commands/a.md": inlineBody("a-inline.sh"),
				".claude/commands/b.md": inlineBody("b-inline.sh"),
				".claude/commands/c.md": inlineBody("c-inline.sh"),
				".claude/commands/d.md": inlineBody("d-inline.sh"),
			},
			wantCalls: 1,
			wantRead:  []string{"a-inline.sh", "b-inline.sh", "c-inline.sh", "d-inline.sh"},
		},
		{
			name: "an irregular entry is refused off the same listing",
			m: fstest.MapFS{
				".claude/commands/a.md":    inlineBody("a-inline.sh"),
				".claude/commands/pipe.md": fifo(inlineBody("pipe-inline.sh").Data),
			},
			wantCalls:    1,
			wantRead:     []string{"a-inline.sh"},
			wantWarnings: 1,
		},
		{
			name: "a symlink pays for the listing resolution needs",
			m: fstest.MapFS{
				".claude/commands/a.md":    inlineBody("a-inline.sh"),
				".claude/commands/link.md": symlink("a.md"),
			},
			wantCalls:    2,
			wantRead:     []string{"a-inline.sh"},
			wantWarnings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			entities, warnings, err := commandEntities(readDirCountingNoLinkFS{m: tt.m, readDirs: &calls})
			if err != nil {
				t.Fatalf("commandEntities() error = %v, want nil", err)
			}
			if got := inlineShellCommands(entities); !slices.Equal(got, tt.wantRead) {
				t.Fatalf("inline shell commands = %v, want %v", got, tt.wantRead)
			}
			if len(warnings) != tt.wantWarnings {
				t.Fatalf("warnings = %+v, want %d", warnings, tt.wantWarnings)
			}
			if calls != tt.wantCalls {
				t.Fatalf("ReadDir calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}
