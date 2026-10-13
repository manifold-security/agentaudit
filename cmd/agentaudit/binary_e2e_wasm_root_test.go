package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var pickedFolderPrefixes = []string{"", "myrepo", ".myrepo"}

var configFolderPicks = []string{".claude", ".cursor", ".codex", ".agents"}

// rootedAtTheirOwnFolder maps each tree whose files all share one folder,
// named like no config folder or plugin marker, to that folder. Declared
// root-relative, such a tree cannot be told from the same folder picked
// directly, so the boundary roots it there and matches the CLI run on that
// folder.
var rootedAtTheirOwnFolder = map[string]string{
	"malicious/claude-plugin-only":       "plugins",
	"malicious/claude-plugin-components": "plugins",
	"nested-plugin":                      "vendor",
	"casing-folder":                      ".Claude",
}

var scannedUnderTwoFolders = map[string]bool{
	"malicious/claude-plugin-only":       true,
	"malicious/claude-plugin-components": true,
	"nested-plugin":                      true,
	"config-less":                        true,
	"marker-only-plugin":                 true,
	"casing-folder":                      true,
}

const (
	rootStatusLine      = `{"statusLine": {"type": "command", "command": "root-status.sh"}}`
	nestedStatusLine    = `{"statusLine": {"type": "command", "command": "nested-status.sh"}}`
	rootMCP             = `{"mcpServers": {"tool": {"command": "node", "args": ["server.js"]}}}`
	vendorManifest      = `{"name": "vendor-plugin", "mcpServers": {"db": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/db"}}}`
	agentsSkill         = "---\nname: demo\ndescription: Run the demo.\n---\n\nRun scripts/demo.sh.\n"
	hookedManifest      = `{"name": "p", "mcpServers": {"tool": {"command": "node", "args": ["server.js"]}}, "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "hook.sh"}]}]}}`
	agentPluginManifest = `{"$schema": "https://agent-plugins.org/schemas/plugin.json", "name": "p"}`
)

// markerDecoyTrees hold only a plugin marker folder with more than its
// manifest inside it.
var markerDecoyTrees = map[string]map[string]string{
	"marker-holding-mcp": {
		".claude-plugin/plugin.json": hookedManifest,
		".claude-plugin/.mcp.json":   "{}",
	},
	"marker-holding-claude-agent": {
		".claude-plugin/plugin.json":         hookedManifest,
		".claude-plugin/.claude/agents/a.md": "---\nname: a\n---\n",
	},
	"marker-holding-codex-hooks": {
		".claude-plugin/plugin.json":       hookedManifest,
		".claude-plugin/.codex/hooks.json": "{}",
	},
	"marker-holding-agents-skill": {
		".claude-plugin/plugin.json":               hookedManifest,
		".claude-plugin/.agents/skills/x/SKILL.md": agentsSkill,
	},
	"marker-holding-cursor-mcp": {
		".claude-plugin/plugin.json":      hookedManifest,
		".claude-plugin/.cursor/mcp.json": "{}",
	},
	"cursor-marker-holding-cursor-hooks": {
		".cursor-plugin/plugin.json":        hookedManifest,
		".cursor-plugin/.cursor/hooks.json": "{}",
	},
}

// markerNamedAgentPlugins are Agent Plugins whose own folder is named like a
// plugin marker: refused when that folder is the picked one, and scanned as
// the CLI scans them when a project folder holding them is picked.
var markerNamedAgentPlugins = map[string]map[string]string{
	"marker-named-agent-plugin": {
		".claude-plugin/plugin.json":       agentPluginManifest,
		".claude-plugin/mcp.json":          rootMCP,
		".claude-plugin/skills/x/SKILL.md": agentsSkill,
	},
	"cursor-marker-named-agent-plugin": {
		".cursor-plugin/plugin.json":       agentPluginManifest,
		".cursor-plugin/mcp.json":          rootMCP,
		".cursor-plugin/skills/x/SKILL.md": agentsSkill,
	},
}

var syntheticRootTrees = map[string]map[string]string{
	"root-relative": {
		".claude/settings.json": rootStatusLine,
		".mcp.json":             rootMCP,
		"src/main.go":           "package main\n",
	},
	"agents-folder": {
		".agents/skills/demo/SKILL.md": agentsSkill,
	},
	"nested-plugin": {
		"vendor/x/.claude-plugin/plugin.json": vendorManifest,
	},
	"root-and-nested-config": {
		".claude/settings.json":          rootStatusLine,
		"apps/web/.claude/settings.json": nestedStatusLine,
	},
	"settings-beside-plugin-manifest": {
		".claude/settings.json":      rootStatusLine,
		".claude-plugin/plugin.json": vendorManifest,
	},
	"config-less": {
		"README.md":   "# demo\n",
		"src/main.go": "package main\n",
	},
	"marker-only-plugin": {
		".claude-plugin/plugin.json": hookedManifest,
	},
	"casing-folder": {
		".Claude/settings.json": rootStatusLine,
	},
}

type parityScan struct {
	name    string
	job     boundaryJob
	project string
	pick    bool
}

// Each scan below decodes through the JS boundary to the document the CLI
// renders for the tree it names as equivalent.
func TestBinaryE2E_TheJSBoundaryReportsAPickedFolderAsTheCLIReportsItsTree(t *testing.T) {
	bin := buildAgentauditBinary(t)
	artifact := buildWASMArtifact(t)
	node := nodeBinary(t)
	shim := wasmExecShim(t)
	driver := writeDifferentialDriver(t)

	trees := rootTrees(t)
	var scans []parityScan
	for name, dir := range trees {
		for _, prefix := range pickedFolderPrefixes {
			project := dir
			if folder, ok := rootedAtTheirOwnFolder[name]; ok && prefix == "" {
				project = filepath.Join(dir, folder)
			}
			scans = append(scans, parityScan{name: fmt.Sprintf("%s under %q", name, prefix), job: boundaryJob{Dir: dir, Prefix: prefix}, project: project})
		}
		held := directoriesIn(t, dir)
		for _, folder := range configFolderPicks {
			if !slices.Contains(held, folder) {
				continue
			}
			pick := t.TempDir()
			copyTree(t, filepath.Join(dir, folder), filepath.Join(pick, folder))
			scans = append(scans, parityScan{name: fmt.Sprintf("%s picked as %s", name, folder), job: boundaryJob{Dir: pick}, project: pick, pick: true})
		}
		if scannedUnderTwoFolders[name] {
			beneath := t.TempDir()
			copyTree(t, dir, filepath.Join(beneath, "b"))
			scans = append(scans, parityScan{name: name + ` under "a/b"`, job: boundaryJob{Dir: dir, Prefix: "a/b"}, project: beneath})
		}
	}

	for name, files := range markerNamedAgentPlugins {
		dir := writeRootTree(t, files)
		for _, prefix := range pickedFolderPrefixes[1:] {
			scans = append(scans, parityScan{name: fmt.Sprintf("%s under %q", name, prefix), job: boundaryJob{Dir: dir, Prefix: prefix}, project: dir})
		}
	}

	jobs := make([]boundaryJob, len(scans))
	for i, scan := range scans {
		jobs[i] = scan.job
	}
	envelopes := scanThroughJSBoundary(t, node, driver, shim, artifact, jobs)

	cliDocs := map[string]any{}
	for _, scan := range scans {
		if _, ok := cliDocs[scan.project]; ok {
			continue
		}
		doc := scanThroughCLI(t, bin, scan.project)
		findings, err := reportFindings(doc)
		if err != nil {
			t.Fatalf("CLI document for %s: %v", scan.project, err)
		}
		if _, err := dropExecutableMarker(findings); err != nil {
			t.Fatalf("CLI document for %s: %v", scan.project, err)
		}
		cliDocs[scan.project] = doc
	}

	compared, picks := 0, 0
	for i, scan := range scans {
		if scan.pick {
			picks++
		}
		t.Run(scan.name, func(t *testing.T) {
			host := boundaryReport(t, envelopes[i])
			if _, err := reportFindings(host); err != nil {
				t.Fatalf("js/wasm document: %v", err)
			}
			for _, diff := range reportDifferences(host, cliDocs[scan.project]) {
				t.Errorf("%s", diff)
			}
			compared++
		})
	}

	if compared != len(scans) {
		t.Fatalf("compared %d of %d scans", compared, len(scans))
	}
	if picks == 0 {
		t.Fatalf("no tree held a config folder to pick, so the config-folder leg compared nothing")
	}
	for name := range rootedAtTheirOwnFolder {
		if _, ok := trees[name]; !ok {
			t.Errorf("rootedAtTheirOwnFolder names %q, which is no tree here: delete the entry rather than carry it", name)
		}
	}
	for name := range scannedUnderTwoFolders {
		if _, ok := trees[name]; !ok {
			t.Errorf("scannedUnderTwoFolders names %q, which is no tree here: delete the entry rather than carry it", name)
		}
	}
}

// A declared set whose project root cannot be settled is refused through the
// JS boundary rather than scanned under a root that leaves config unread.
func TestBinaryE2E_TheJSBoundaryRefusesASetWhoseRootItCannotSettle(t *testing.T) {
	artifact := buildWASMArtifact(t)
	node := nodeBinary(t)
	shim := wasmExecShim(t)
	driver := writeDifferentialDriver(t)

	const (
		below     = "only below the project root"
		ambiguous = "or its parent is the project root is ambiguous"
		marker    = "named like a plugin marker"
	)
	type refusal struct {
		name string
		job  boundaryJob
		want string
	}
	cases := []refusal{
		{
			name: "a project folder named .claude",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"settings.json":         `{"permissions": {"defaultMode": "default"}}`,
				".claude/settings.json": rootStatusLine,
			}), Prefix: ".claude"},
			want: ambiguous,
		},
		{
			name: "a project folder named .cursor holding a .claude folder",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"mcp.json":              rootMCP,
				".claude/settings.json": rootStatusLine,
			}), Prefix: ".cursor"},
			want: ambiguous,
		},
		{
			name: "a project folder named .claude whose decoy sorts last",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"agents/a.md": "---\nname: a\n---\n",
				"plugin.json": hookedManifest,
			}), Prefix: ".claude"},
			want: ambiguous,
		},
		{
			name: "a project folder named .agents whose decoy sorts last",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"README.md":   "# demo\n",
				"plugin.json": hookedManifest,
			}), Prefix: ".agents"},
			want: ambiguous,
		},
		{
			name: "a parent pick holding a manifest inside .cursor/hooks",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"repo/.cursor/hooks/.cursor-plugin/plugin.json": hookedManifest,
			}), Prefix: "projects"},
			want: below,
		},
		{
			name: "a parent pick holding a Claude manifest inside .cursor/hooks",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"repo/.cursor/hooks/.claude-plugin/plugin.json": hookedManifest,
			}), Prefix: "projects"},
			want: below,
		},
		{
			name: "a project holding only nested config",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				"README.md":                      "# demo\n",
				"apps/web/.claude/settings.json": nestedStatusLine,
			}), Prefix: "myrepo"},
			want: below,
		},
		{
			name: "a plugin repo with a stray marker .mcp.json",
			job: boundaryJob{Dir: writeRootTree(t, map[string]string{
				".claude-plugin/plugin.json": hookedManifest,
				".claude-plugin/.mcp.json":   "{}",
				"hooks/hooks.json":           `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "stop.sh"}]}]}}`,
			}), Prefix: "myrepo"},
			want: below,
		},
	}
	for name, files := range markerDecoyTrees {
		dir := writeRootTree(t, files)
		cases = append(cases, refusal{name: name + ` under ""`, job: boundaryJob{Dir: dir}, want: marker})
		for _, prefix := range pickedFolderPrefixes[1:] {
			cases = append(cases, refusal{name: fmt.Sprintf("%s under %q", name, prefix), job: boundaryJob{Dir: dir, Prefix: prefix}, want: below})
		}
	}
	for name, files := range markerNamedAgentPlugins {
		cases = append(cases, refusal{name: name + ` under ""`, job: boundaryJob{Dir: writeRootTree(t, files)}, want: marker})
	}
	for name, dir := range rootTrees(t) {
		if !scannedUnderTwoFolders[name] {
			cases = append(cases, refusal{name: name + ` under "a/b"`, job: boundaryJob{Dir: dir, Prefix: "a/b"}, want: below})
		}
	}

	jobs := make([]boundaryJob, len(cases))
	for i, tc := range cases {
		jobs[i] = tc.job
	}
	envelopes := scanThroughJSBoundary(t, node, driver, shim, artifact, jobs)

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if envelopes[i]["ok"] != false {
				t.Fatalf("envelope = %v, want a refusal", envelopes[i])
			}
			if msg, _ := envelopes[i]["error"].(string); !strings.Contains(msg, tc.want) {
				t.Fatalf("error = %q, want it to contain %q", msg, tc.want)
			}
		})
	}
}

func rootTrees(t *testing.T) map[string]string {
	t.Helper()

	trees := fixtureRootTrees(t)
	for name, files := range syntheticRootTrees {
		trees[name] = writeRootTree(t, files)
	}
	return trees
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()

	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatalf("copying %s to %s: %v", src, dst, err)
	}
}

func fixtureRootTrees(t *testing.T) map[string]string {
	t.Helper()

	root := resolveFixture(t, filepath.Join("..", "..", "testdata"))
	trees := map[string]string{}
	for _, group := range directoriesIn(t, root) {
		for _, tree := range directoriesIn(t, filepath.Join(root, group)) {
			trees[group+"/"+tree] = filepath.Join(root, group, tree)
		}
	}
	if len(trees) == 0 {
		t.Fatalf("no fixture tree found under %s; an empty enumeration must not pass silently", root)
	}
	return trees
}

func directoriesIn(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) error = %v", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names
}

func writeRootTree(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("os.MkdirAll(%q) error = %v", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", target, err)
		}
	}
	return dir
}
