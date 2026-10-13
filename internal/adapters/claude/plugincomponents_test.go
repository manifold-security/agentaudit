package claude

import (
	"errors"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// pluginSkillSource puts a frontmatter hook and a body placeholder in one
// file, because Claude Code honours each for a plugin-shipped skill.
const pluginSkillSource = "---\nname: demo\nhooks:\n  SessionStart:\n" +
	"    - hooks:\n        - type: command\n          command: skill-hook.sh\n" +
	"---\nRun !`skill-inline.sh` before anything else.\n"

const pluginCommandSource = "---\nname: release\nhooks:\n  SessionStart:\n" +
	"    - hooks:\n        - type: command\n          command: command-hook.sh\n" +
	"---\nRun !`command-inline.sh` before anything else.\n"

func hookCommands(entities []ir.Entity) []string {
	var out []string
	for _, e := range entities {
		if h, ok := e.(ir.Hook); ok {
			out = append(out, h.Command)
		}
	}
	sort.Strings(out)
	return out
}

func inlineShellCommands(entities []ir.Entity) []string {
	var out []string
	for _, e := range entities {
		if s, ok := e.(ir.InlineShell); ok {
			out = append(out, s.Command)
		}
	}
	sort.Strings(out)
	return out
}

func skillNames(entities []ir.Entity) []string {
	var out []string
	for _, e := range entities {
		if s, ok := e.(ir.Skill); ok {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// inlineBody and skillBody give each fixture a placeholder command unique to
// it, so "the walk reached this file" is provable from the emitted command
// rather than inferred from a count.
func inlineBody(cmd string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("Run !`" + cmd + "` now.\n")}
}

func skillBody(name, cmd string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("---\nname: " + name + "\n---\nRun !`" + cmd + "` now.\n")}
}

// Claude Code stops scanning the default commands/ once the manifest names
// its own, so reporting it attributes capabilities to an unloaded surface.
func TestManifestCommandsKeyReplacesDefaultDirectory(t *testing.T) {
	cases := []struct {
		name    string
		declare string
	}{
		{name: "string form names a directory", declare: `"./custom"`},
		{name: "array form names a directory", declare: `["./custom"]`},
		{name: "string form names a single file", declare: `"./custom/cmd.md"`},
		{name: "array form names a single file", declare: `["./custom/cmd.md"]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{
					Data: []byte(`{"name":"toolkit","commands":` + tc.declare + `}`),
				},
				"plugins/toolkit/commands/default.md": inlineBody("default-cmd.sh"),
				"plugins/toolkit/custom/cmd.md":       inlineBody("custom-cmd.sh"),
			}

			entities, warnings := pluginEntities(fsys)
			if len(warnings) != 0 {
				t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
			}

			got := inlineShellCommands(entities)
			if want := []string{"custom-cmd.sh"}; !slices.Equal(got, want) {
				t.Fatalf("inline shell commands = %v, want %v (the default commands/ must NOT be walked)", got, want)
			}
		})
	}
}

// Reading the skills key as a replacement goes blind to what a plugin ships.
func TestManifestSkillsKeyAddsToDefaultDirectory(t *testing.T) {
	cases := []struct {
		name    string
		declare string
	}{
		{name: "string form", declare: `"./extra"`},
		{name: "array form", declare: `["./extra"]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{
					Data: []byte(`{"name":"toolkit","skills":` + tc.declare + `}`),
				},
				"plugins/toolkit/skills/a/SKILL.md": skillBody("skill-a", "default-skill.sh"),
				"plugins/toolkit/extra/b/SKILL.md":  skillBody("skill-b", "declared-skill.sh"),
			}

			entities, warnings := pluginEntities(fsys)
			if len(warnings) != 0 {
				t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
			}

			got := inlineShellCommands(entities)
			if want := []string{"declared-skill.sh", "default-skill.sh"}; !slices.Equal(got, want) {
				t.Errorf("inline shell commands = %v, want %v (the default skills/ is always scanned too)", got, want)
			}
			gotNames := skillNames(entities)
			if want := []string{"skill-a", "skill-b"}; !slices.Equal(gotNames, want) {
				t.Errorf("skill names = %v, want %v", gotNames, want)
			}
		})
	}
}

// A plugin ships its root SKILL.md as a skill only with neither a skills/
// directory nor a skills key; otherwise it is a surface that never loads.
func TestPluginRootSkillFallback(t *testing.T) {
	cases := []struct {
		name      string
		manifest  string
		extra     map[string]*fstest.MapFile
		want      []string
		wantSkill []string
	}{
		{
			name:      "no skills directory and no skills key loads the root SKILL.md",
			manifest:  `{"name":"toolkit"}`,
			want:      []string{"root-skill.sh"},
			wantSkill: []string{"root-skill"},
		},
		{
			name:     "a skills directory suppresses the root SKILL.md",
			manifest: `{"name":"toolkit"}`,
			extra: map[string]*fstest.MapFile{
				"plugins/toolkit/skills/a/SKILL.md": skillBody("skill-a", "default-skill.sh"),
			},
			want:      []string{"default-skill.sh"},
			wantSkill: []string{"skill-a"},
		},
		{
			name:     "a skills key suppresses the root SKILL.md",
			manifest: `{"name":"toolkit","skills":"./extra"}`,
			extra: map[string]*fstest.MapFile{
				"plugins/toolkit/extra/b/SKILL.md": skillBody("skill-b", "declared-skill.sh"),
			},
			want:      []string{"declared-skill.sh"},
			wantSkill: []string{"skill-b"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(tc.manifest)},
				"plugins/toolkit/SKILL.md":                   skillBody("root-skill", "root-skill.sh"),
			}
			for p, f := range tc.extra {
				fsys[p] = f
			}

			entities, warnings := pluginEntities(fsys)
			if len(warnings) != 0 {
				t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
			}

			if got := inlineShellCommands(entities); !slices.Equal(got, tc.want) {
				t.Fatalf("inline shell commands = %v, want %v", got, tc.want)
			}
			// Routed through a command walk the body still yields its
			// inline shell, so only the ir.Skill catches the swap.
			if got := skillNames(entities); !slices.Equal(got, tc.wantSkill) {
				t.Errorf("skill names = %v, want %v", got, tc.wantSkill)
			}
		})
	}
}

// The manifest documents a component path as either a directory or a single
// .md file, so the file form must be admitted rather than warned.
func TestManifestAgentsKeyNamingSingleFile(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit","agents":"./custom/reviewer.md"}`)},
		"plugins/toolkit/custom/reviewer.md":         &fstest.MapFile{Data: []byte("---\nname: reviewer\n---\n")},
	}

	entities, warnings := pluginEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
	}

	var names []string
	for _, e := range entities {
		if s, ok := e.(ir.Subagent); ok {
			names = append(names, s.Name)
		}
	}
	if !slices.Equal(names, []string{"reviewer"}) {
		t.Errorf("subagent names = %v, want [reviewer]", names)
	}
}

// Each silent case still asserts a surface that fires, since zero warnings
// is also what a dead walk produces.
func TestPluginComponentDeclaredPathMissingWarnsWhileMissingDefaultStaysSilent(t *testing.T) {
	cases := []struct {
		name            string
		manifest        string
		wantWarningFile string
		wantCommands    []string
	}{
		{
			name:            "declared skills path is missing",
			manifest:        `{"name":"toolkit","skills":"./nowhere"}`,
			wantWarningFile: "plugins/toolkit/nowhere",
			wantCommands:    []string{"default-skill.sh"},
		},
		{
			name:            "declared commands path is missing",
			manifest:        `{"name":"toolkit","commands":"./nowhere"}`,
			wantWarningFile: "plugins/toolkit/nowhere",
			wantCommands:    []string{"default-skill.sh"},
		},
		{
			name:         "default commands directory is missing",
			manifest:     `{"name":"toolkit"}`,
			wantCommands: []string{"default-skill.sh"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(tc.manifest)},
				"plugins/toolkit/skills/a/SKILL.md":          skillBody("skill-a", "default-skill.sh"),
			}

			entities, warnings := pluginEntities(fsys)

			if got := inlineShellCommands(entities); !slices.Equal(got, tc.wantCommands) {
				t.Fatalf("inline shell commands = %v, want %v", got, tc.wantCommands)
			}

			if tc.wantWarningFile == "" {
				if len(warnings) != 0 {
					t.Fatalf("pluginEntities() warnings = %+v, want none for a missing DEFAULT location", warnings)
				}
				return
			}
			if len(warnings) != 1 {
				t.Fatalf("pluginEntities() warnings = %+v, want exactly 1 for the declared-but-missing path", warnings)
			}
			if warnings[0].File != tc.wantWarningFile {
				t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, tc.wantWarningFile)
			}
		})
	}
}

func TestPluginComponentDeclaredPathEscapingRootWarnsAndSkips(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
	}{
		{name: "skills", manifest: `{"name":"toolkit","skills":"../../outside"}`},
		{name: "commands", manifest: `{"name":"toolkit","commands":"../../outside"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(tc.manifest)},
				"plugins/toolkit/skills/a/SKILL.md":          skillBody("skill-a", "default-skill.sh"),
				"outside/leaked/SKILL.md":                    skillBody("leaked", "leaked.sh"),
				"outside/leaked.md":                          inlineBody("leaked.sh"),
			}

			entities, warnings := pluginEntities(fsys)

			got := inlineShellCommands(entities)
			if want := []string{"default-skill.sh"}; !slices.Equal(got, want) {
				t.Fatalf("inline shell commands = %v, want %v (nothing outside the plugin root may be read)", got, want)
			}
			if len(warnings) != 1 {
				t.Fatalf("pluginEntities() warnings = %+v, want exactly 1 for the escaping path", warnings)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", warnings[0].Err)
			}
		})
	}
}

func symlink(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink}
}

// Following a symlink would report out-of-tree content as if the in-tree
// plugin shipped it, and fs.WalkDir cannot refuse it on its own: the stat on
// its walk root follows the link, and so does the one behind fs.ReadFile.
func TestPluginComponentSymlinkedTargetsAreRefused(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		files    map[string]*fstest.MapFile
	}{
		{
			name: "symlinked skills directory",
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/skills":              symlink("../../outside"),
				"plugins/toolkit/commands/release.md": inlineBody("in-tree.sh"),
			},
		},
		{
			name: "symlinked commands directory",
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/commands":          symlink("../../outside"),
				"plugins/toolkit/skills/a/SKILL.md": skillBody("skill-a", "in-tree.sh"),
			},
		},
		{
			name:     "symlinked intermediate component on a declared skills path",
			manifest: `{"name":"toolkit","skills":"./mid/leaked"}`,
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/mid":                 symlink("../../outside"),
				"plugins/toolkit/commands/release.md": inlineBody("in-tree.sh"),
			},
		},
		{
			name:     "symlinked intermediate component on a declared commands path",
			manifest: `{"name":"toolkit","commands":"./mid/leaked.md"}`,
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/mid":               symlink("../../outside"),
				"plugins/toolkit/skills/a/SKILL.md": skillBody("skill-a", "in-tree.sh"),
			},
		},
		{
			name: "symlinked SKILL.md inside the skills directory",
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/skills/linked/SKILL.md": symlink("../../../../outside/leaked/SKILL.md"),
				"plugins/toolkit/skills/real/SKILL.md":   skillBody("skill-real", "in-tree.sh"),
			},
		},
		{
			name: "symlinked skill folder inside the skills directory",
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/skills/linked":        symlink("../../../outside/leaked"),
				"plugins/toolkit/skills/real/SKILL.md": skillBody("skill-real", "in-tree.sh"),
			},
		},
		{
			name: "symlinked command file inside the commands directory",
			files: map[string]*fstest.MapFile{
				"plugins/toolkit/commands/linked.md": symlink("../../../outside/leaked.md"),
				"plugins/toolkit/commands/real.md":   inlineBody("in-tree.sh"),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := tc.manifest
			if manifest == "" {
				manifest = `{"name":"toolkit"}`
			}
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(manifest)},
				"outside/leaked/SKILL.md":                    skillBody("leaked", "leaked.sh"),
				"outside/leaked.md":                          inlineBody("leaked.sh"),
			}
			for p, f := range tc.files {
				fsys[p] = f
			}

			entities, warnings := pluginEntities(fsys)

			got := inlineShellCommands(entities)
			if want := []string{"in-tree.sh"}; !slices.Equal(got, want) {
				t.Fatalf("inline shell commands = %v, want %v (a symlinked target must never be read)", got, want)
			}
			if len(warnings) != 1 {
				t.Fatalf("pluginEntities() warnings = %+v, want exactly 1 for the refused symlink", warnings)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", warnings[0].Err)
			}
		})
	}
}

// unterminatedFrontmatter opens a --- block and leaves it unclosed, so there
// is no body boundary and the file can be reported as a warning.
const unterminatedFrontmatter = "---\nname: broken\nRun !`unreachable.sh` now.\n"

func TestPluginComponentMalformedFileWarnsAndSiblingsSurvive(t *testing.T) {
	cases := []struct {
		name    string
		broken  string
		sibling string
		file    *fstest.MapFile
	}{
		{
			name:    "skills",
			broken:  "plugins/toolkit/skills/broken/SKILL.md",
			sibling: "plugins/toolkit/skills/good/SKILL.md",
			file:    skillBody("good", "sibling.sh"),
		},
		{
			name:    "commands",
			broken:  "plugins/toolkit/commands/broken.md",
			sibling: "plugins/toolkit/commands/good.md",
			file:    inlineBody("sibling.sh"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
				tc.broken:  &fstest.MapFile{Data: []byte(unterminatedFrontmatter)},
				tc.sibling: tc.file,
			}

			entities, warnings := pluginEntities(fsys)

			got := inlineShellCommands(entities)
			if want := []string{"sibling.sh"}; !slices.Equal(got, want) {
				t.Fatalf("inline shell commands = %v, want %v (the sibling must survive the malformed file)", got, want)
			}
			if len(warnings) != 1 {
				t.Fatalf("pluginEntities() warnings = %+v, want exactly 1 for the malformed file", warnings)
			}
			if warnings[0].File != tc.broken {
				t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, tc.broken)
			}
		})
	}
}

// A plugin skill's hooks DO surface while the agent's stay suppressed. The
// asymmetry is the risk — widening it hides capabilities, narrowing it
// invents them.
func TestPluginAgentHooksStaySuppressedWhileSkillHooksSurface(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
		"plugins/toolkit/agents/reviewer.md": &fstest.MapFile{Data: []byte(
			"---\nname: reviewer\npermissionMode: bypassPermissions\nhooks:\n  SessionStart:\n" +
				"    - hooks:\n        - type: command\n          command: agent-hook.sh\n" +
				"mcpServers:\n  db:\n    command: agent-mcp-server\n---\n",
		)},
		"plugins/toolkit/skills/demo/SKILL.md": &fstest.MapFile{Data: []byte(pluginSkillSource)},
	}

	entities, warnings := pluginEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
	}

	if got, want := hookCommands(entities), []string{"skill-hook.sh"}; !slices.Equal(got, want) {
		t.Fatalf("hook commands = %v, want %v", got, want)
	}

	var sawAgent bool
	for _, e := range entities {
		switch v := e.(type) {
		case ir.Subagent:
			sawAgent = true
		case ir.MCPServer:
			t.Errorf("pluginEntities() emitted %+v; a plugin agent's mcpServers must stay suppressed", v)
		case ir.PermissionMode:
			t.Errorf("pluginEntities() emitted %+v; a plugin agent's permissionMode must stay suppressed", v)
		}
	}
	if !sawAgent {
		t.Fatal("pluginEntities() emitted no ir.Subagent; the agent walk did not run, so nothing above proves suppression")
	}
}

func TestPluginSkillsDefaultDirectoryEmitsHookInlineShellAndPresence(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
		"plugins/toolkit/skills/demo/SKILL.md":       &fstest.MapFile{Data: []byte(pluginSkillSource)},
	}

	entities, warnings := pluginEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
	}

	if got, want := hookCommands(entities), []string{"skill-hook.sh"}; !slices.Equal(got, want) {
		t.Errorf("hook commands = %v, want %v", got, want)
	}
	if got, want := inlineShellCommands(entities), []string{"skill-inline.sh"}; !slices.Equal(got, want) {
		t.Errorf("inline shell commands = %v, want %v", got, want)
	}
	if got, want := skillNames(entities), []string{"demo"}; !slices.Equal(got, want) {
		t.Errorf("skill names = %v, want %v", got, want)
	}

	const wantFile = "plugins/toolkit/skills/demo/SKILL.md"
	for _, e := range entities {
		switch v := e.(type) {
		case ir.Hook:
			if v.Location.File != wantFile {
				t.Errorf("ir.Hook.Location.File = %q, want %q", v.Location.File, wantFile)
			}
		case ir.InlineShell:
			if v.Location.File != wantFile {
				t.Errorf("ir.InlineShell.Location.File = %q, want %q", v.Location.File, wantFile)
			}
		case ir.Skill:
			if v.Location.File != wantFile {
				t.Errorf("ir.Skill.Location.File = %q, want %q", v.Location.File, wantFile)
			}
		}
	}
}

func TestPluginCommandsDefaultDirectoryEmitsHookAndInlineShellWithoutPresence(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
		"plugins/toolkit/commands/release.md":        &fstest.MapFile{Data: []byte(pluginCommandSource)},
	}

	entities, warnings := pluginEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("pluginEntities() warnings = %+v, want none", warnings)
	}

	if got, want := hookCommands(entities), []string{"command-hook.sh"}; !slices.Equal(got, want) {
		t.Errorf("hook commands = %v, want %v", got, want)
	}
	if got, want := inlineShellCommands(entities), []string{"command-inline.sh"}; !slices.Equal(got, want) {
		t.Errorf("inline shell commands = %v, want %v", got, want)
	}
	if names := skillNames(entities); len(names) != 0 {
		t.Errorf("skill names = %v, want none: a command file has no presence entity", names)
	}

	const wantFile = "plugins/toolkit/commands/release.md"
	for _, e := range entities {
		switch v := e.(type) {
		case ir.Hook:
			if v.Location.File != wantFile {
				t.Errorf("ir.Hook.Location.File = %q, want %q", v.Location.File, wantFile)
			}
		case ir.InlineShell:
			if v.Location.File != wantFile {
				t.Errorf("ir.InlineShell.Location.File = %q, want %q", v.Location.File, wantFile)
			}
		}
	}
}

// Project skills and commands read a symlinked .md where plugin-shipped ones
// refuse it; pinning both halves stops a consolidation of the two walks from
// silently un-scanning an in-tree layout the tool supports.
func TestProjectMarkdownReadsSymlinksWherePluginRefusesThem(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/skills/linked/SKILL.md": symlink("../../../shared/SKILL.md"),
		".claude/commands/linked.md":     symlink("../../shared/cmd.md"),
		"shared/SKILL.md":                skillBody("shared-skill", "project-skill-inline.sh"),
		"shared/cmd.md":                  inlineBody("project-command-inline.sh"),

		"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
		"plugins/toolkit/skills/linked/SKILL.md":     symlink("../../../../shared/SKILL.md"),
		"plugins/toolkit/commands/linked.md":         symlink("../../../shared/cmd.md"),
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	got := inlineShellCommands(entities)
	want := []string{"project-command-inline.sh", "project-skill-inline.sh"}
	if !slices.Equal(got, want) {
		t.Errorf("inline shell commands = %v, want %v (the project surfaces must still read a symlinked .md, and the plugin ones must not)", got, want)
	}

	refused := map[string]bool{}
	for _, w := range warnings {
		refused[w.File] = true
	}
	for _, p := range []string{"plugins/toolkit/skills/linked/SKILL.md", "plugins/toolkit/commands/linked.md"} {
		if !refused[p] {
			t.Errorf("no warning for %q; warned paths = %v", p, refused)
		}
	}
	for _, p := range []string{".claude/skills/linked/SKILL.md", ".claude/commands/linked.md"} {
		if refused[p] {
			t.Errorf("project path %q was refused; it must still be read", p)
		}
	}
}

func TestManifestSkillsPathNamingNonSkillFileWarns(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit","skills":"./extra/mine.md"}`)},
		"plugins/toolkit/extra/mine.md":              skillBody("mine", "declared-file-inline.sh"),
		"plugins/toolkit/skills/a/SKILL.md":          skillBody("skill-a", "default-inline.sh"),
	}

	entities, warnings := pluginEntities(fsys)

	if got := inlineShellCommands(entities); !slices.Equal(got, []string{"default-inline.sh"}) {
		t.Errorf("inline shell commands = %v, want [default-inline.sh]", got)
	}

	var warned bool
	for _, w := range warnings {
		if w.File == "plugins/toolkit/extra/mine.md" {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no warning naming the declared non-skill path; warnings = %+v", warnings)
	}
}

// The sibling fixture would surface if the selector widened.
func TestSkillSiblingMarkdownStaysUnread(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/skills/demo/SKILL.md":     skillBody("demo", "skill-inline.sh"),
		".claude/skills/demo/reference.md": inlineBody("sibling-inline.sh"),
	}

	entities, _, err := skillEntities(fsys)
	if err != nil {
		t.Fatalf("skillEntities() error = %v, want nil", err)
	}
	if got := inlineShellCommands(entities); !slices.Equal(got, []string{"skill-inline.sh"}) {
		t.Errorf("inline shell commands = %v, want [skill-inline.sh] only", got)
	}
}

// A folder link on a Markdown surface is named rather than followed or
// skipped, and a real folder in its place still yields its entity, so the
// warning stands for what the link hides.
func TestParseNamesALinkedMarkdownFolderAndReadsARealOne(t *testing.T) {
	const sibling = ".claude/commands/real.md"
	agentBody := &fstest.MapFile{Data: []byte("---\nname: helper\ndescription: helps\n---\nbody\n")}

	surfaces := []struct {
		name   string
		dir    string
		folder string
		file   string
		body   *fstest.MapFile
	}{
		{name: "project agents", dir: ".claude/agents", folder: "team", file: "helper.md", body: agentBody},
		{name: "plugin commands", dir: "plugins/toolkit/commands", folder: "ns", file: "deploy.md", body: inlineBody("shared.sh")},
		{name: "plugin agents", dir: "plugins/toolkit/agents", folder: "team", file: "helper.md", body: agentBody},
		{name: "project skills under a Markdown name", dir: skillsDir, folder: "evil.md", file: skillFileName, body: skillBody("shared", "shared.sh")},
	}

	for _, s := range surfaces {
		base := func() fstest.MapFS {
			return fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
				sibling: inlineBody("in-tree.sh"),
			}
		}
		folder := s.dir + "/" + s.folder

		t.Run(s.name+"/linked", func(t *testing.T) {
			fsys := base()
			fsys[folder] = symlink(strings.Repeat("../", strings.Count(folder, "/")) + "shared/" + s.folder)
			fsys["shared/"+s.folder+"/"+s.file] = s.body

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			for _, e := range entities {
				if file := ir.LocationOf(e).File; strings.HasPrefix(file, "shared/") || strings.HasPrefix(file, folder) {
					t.Fatalf("entity %+v was read through the link", e)
				}
			}
			if got := inlineShellCommands(entities); !slices.Equal(got, []string{"in-tree.sh"}) {
				t.Fatalf("inline shell commands = %v, want the sibling's", got)
			}
			if len(warnings) != 1 || warnings[0].File != folder {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, folder)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Fatalf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", warnings[0].Err)
			}
		})

		t.Run(s.name+"/real", func(t *testing.T) {
			fsys := base()
			fsys[folder+"/"+s.file] = s.body

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			if !slices.ContainsFunc(entities, func(e ir.Entity) bool { return ir.LocationOf(e).File == folder+"/"+s.file }) {
				t.Fatalf("entities = %+v, want one from %q", entities, folder+"/"+s.file)
			}
		})
	}
}

// A link over nothing hides nothing, so the adapter leaves it to discovery,
// which names the dangling path without degrading the scan.
func TestParseLeavesALinkOverNothingToDiscovery(t *testing.T) {
	const sibling = ".claude/commands/real.md"

	for _, link := range []string{
		skillsDir + "/linked",
		skillsDir + "/real/scripts/tool",
		commandsDir + "/linked",
		agentsDir + "/team",
		"plugins/toolkit/commands/ns",
		"plugins/toolkit/agents/team",
		"plugins/toolkit/skills/linked",
	} {
		t.Run(link, func(t *testing.T) {
			entities, warnings, err := New().Parse(fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
				sibling: inlineBody("in-tree.sh"),
				link:    symlink("nowhere"),
			})
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none for a link over nothing", warnings)
			}
			if got := inlineShellCommands(entities); !slices.Equal(got, []string{"in-tree.sh"}) {
				t.Fatalf("inline shell commands = %v, want the sibling's", got)
			}
		})
	}
}

// A link counts only where it could hide something: a directory target, or
// a name the surface would read. Under any other name a link over a file or
// a pipe shows as much as the file itself, which is nothing.
func TestParseRefusesALinkOnlyWhereItCouldHideSomething(t *testing.T) {
	tests := []struct {
		link     string
		target   string
		wantWarn bool
	}{
		{link: "plugins/toolkit/skills/s/reference.md", target: "file"},
		{link: agentsDir + "/notes.txt", target: "file"},
		{link: agentsDir + "/notes.txt", target: "pipe"},
		{link: "plugins/toolkit/commands/notes.txt", target: "file"},
		{link: "plugins/toolkit/agents/notes.txt", target: "file"},
		{link: skillsDir + "/s/notes.txt", target: "file"},
		{link: skillsDir + "/s/notes.md", target: "pipe"},
		{link: skillsDir + "/s/notes.md", target: "exec"},
		{link: skillsDir + "/s/tool", target: "pipe"},
		{link: commandsDir + "/notes.txt", target: "file"},
		{link: skillsDir + "/s/notes.txt", target: "exec", wantWarn: true},
		{link: skillsDir + "/s/tool", target: "file", wantWarn: true},
		{link: skillsDir + "/s/.setup", target: "file", wantWarn: true},
		{link: agentsDir + "/notes.txt", target: "dir", wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.link+"->"+tt.target, func(t *testing.T) {
			entities, warnings, err := New().Parse(fstest.MapFS{
				"plugins/toolkit/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"toolkit"}`)},
				commandsDir + "/real.md":                     inlineBody("in-tree.sh"),
				tt.link:                                      symlink(strings.Repeat("../", strings.Count(tt.link, "/")) + "shared/" + tt.target),
				"shared/file":                                &fstest.MapFile{Data: []byte("notes\n")},
				"shared/exec":                                &fstest.MapFile{Data: []byte("notes\n"), Mode: 0o755},
				"shared/pipe":                                &fstest.MapFile{Mode: fs.ModeNamedPipe},
				"shared/dir/helper.md":                       &fstest.MapFile{Data: []byte("---\nname: helper\n---\n")},
			})
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if got := inlineShellCommands(entities); !slices.Equal(got, []string{"in-tree.sh"}) {
				t.Fatalf("inline shell commands = %v, want the sibling's", got)
			}
			switch {
			case !tt.wantWarn && len(warnings) != 0:
				t.Fatalf("warnings = %+v, want none", warnings)
			case tt.wantWarn && (len(warnings) != 1 || warnings[0].File != tt.link || !errors.Is(warnings[0].Err, adapter.ErrUnreadable)):
				t.Fatalf("warnings = %+v, want exactly one refusal naming %q", warnings, tt.link)
			}
		})
	}
}

// The Markdown walk refuses a link it selects on its own, so the payload walk
// over the same tree must not name it a second time.
func TestParseNamesALinkTheMarkdownWalkSelectsOnce(t *testing.T) {
	for _, link := range []string{skillsDir + "/s/" + skillFileName, commandsDir + "/deploy.md"} {
		t.Run(link, func(t *testing.T) {
			_, warnings, err := New().Parse(fstest.MapFS{
				link:                   symlink(strings.Repeat("../", strings.Count(link, "/")) + "shared/dir"),
				"shared/dir/helper.md": &fstest.MapFile{Data: []byte("x\n")},
			})
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(warnings) != 1 || warnings[0].File != link {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
			}
		})
	}
}
