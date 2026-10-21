package adapter

import "testing"

// Signature matching holds at a path-segment boundary, not a string prefix.
func TestMatches(t *testing.T) {
	rootMCP := []Signature{{File: ".mcp.json"}}
	claudeTree := []Signature{{Dir: ".claude", Recursive: true}}

	tests := []struct {
		name string
		path string
		sigs []Signature
		want bool
	}{
		{"root exact file matches", ".mcp.json", rootMCP, true},
		{"direct child of recursive dir matches", ".claude/settings.json", claudeTree, true},
		{"deeply nested descendant matches", ".claude/a/b/c.json", claudeTree, true},
		{"bare recursive dir itself matches", ".claude", claudeTree, true},

		{"right filename wrong location rejected", "sub/.mcp.json", rootMCP, false},
		{"different root dir rejected", ".cursor/mcp.json", claudeTree, false},
		{"segment-boundary suffix dir rejected", ".claude-evil/x", claudeTree, false},
		{"segment-boundary numeric-suffix dir rejected", ".claude2/mcp.json", claudeTree, false},

		{"empty signature list never matches", ".mcp.json", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Matches(tt.path, tt.sigs)
			if got != tt.want {
				t.Fatalf("Matches(%q, %v) = %v, want %v", tt.path, tt.sigs, got, tt.want)
			}
		})
	}
}

// An AnyDepth signature matches Dir/File at any depth, fs.FS root included.
func TestSignatureAnyDepthMode(t *testing.T) {
	sigs := []Signature{{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true}}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"root-level manifest matches", ".claude-plugin/plugin.json", true},
		{"one level nested matches", "plugins/foo/.claude-plugin/plugin.json", true},
		{"arbitrarily deep nested matches", "a/b/c/d/.claude-plugin/plugin.json", true},

		{"segment-boundary suffix dir rejected", "evil.claude-plugin/plugin.json", false},
		{"segment-boundary suffix dir rejected nested", "x/evil.claude-plugin/plugin.json", false},
		{"file mismatch rejected", ".claude-plugin/README.md", false},
		{"extra nested segment rejected", ".claude-plugin/nested/plugin.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Matches(tt.path, sigs); got != tt.want {
				t.Fatalf("Matches(%q, %v) = %v, want %v", tt.path, sigs, got, tt.want)
			}
		})
	}
}

// The zero value of AnyDepth leaves depth-exact matching unchanged.
func TestSignatureAnyDepthZeroValueUnchanged(t *testing.T) {
	tests := []struct {
		name string
		sig  Signature
		path string
		want bool
	}{
		{"settings.json exact match", Signature{Dir: ".claude", File: "settings.json"}, ".claude/settings.json", true},
		{"settings.local.json exact match", Signature{Dir: ".claude", File: "settings.local.json"}, ".claude/settings.local.json", true},
		{"root .mcp.json exact match", Signature{Dir: ".", File: ".mcp.json"}, ".mcp.json", true},
		{"recursive agents dir matches nested", Signature{Dir: ".claude/agents", Recursive: true}, ".claude/agents/a/b.md", true},
		{"recursive skills dir matches nested", Signature{Dir: ".claude/skills", Recursive: true}, ".claude/skills/a/SKILL.md", true},
		{"recursive commands dir matches nested", Signature{Dir: ".claude/commands", Recursive: true}, ".claude/commands/deploy.md", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sig.AnyDepth {
				t.Fatalf("fixture bug: %s must have AnyDepth zero-valued (false)", tt.name)
			}
			if got := Matches(tt.path, []Signature{tt.sig}); got != tt.want {
				t.Fatalf("Matches(%q, %v) = %v, want %v", tt.path, tt.sig, got, tt.want)
			}
		})
	}
}

// A directory-typed entry matches an AnyDepth signature and none of the
// other modes.
func TestMatchesEntryDirectoryTypedMarker(t *testing.T) {
	manifest := []Signature{{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true}}
	settings := []Signature{{Dir: ".claude", File: "settings.json"}}
	claudeTree := []Signature{{Dir: ".claude/agents", Recursive: true}}

	tests := []struct {
		name  string
		path  string
		isDir bool
		sigs  []Signature
		want  bool
	}{
		{"directory-typed manifest at root matches AnyDepth", ".claude-plugin/plugin.json", true, manifest, true},
		{"directory-typed manifest nested matches AnyDepth", "plugins/foo/.claude-plugin/plugin.json", true, manifest, true},
		{"file-typed manifest still matches AnyDepth", ".claude-plugin/plugin.json", false, manifest, true},

		{"recursive dir itself does not match as a directory entry", ".claude/agents", true, claudeTree, false},
		{"exact-file signature does not match as a directory entry", ".claude/settings.json", true, settings, false},
		{"exact-file signature still matches as a file entry", ".claude/settings.json", false, settings, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesEntry(tt.path, tt.isDir, tt.sigs)
			if got != tt.want {
				t.Fatalf("MatchesEntry(%q, isDir=%v, %v) = %v, want %v", tt.path, tt.isDir, tt.sigs, got, tt.want)
			}
		})
	}
}

// Matches and MatchesEntry agree on file entries.
func TestMatchesIsMatchesEntryForFiles(t *testing.T) {
	sigs := []Signature{
		{Dir: ".claude", File: "settings.json"},
		{Dir: ".claude/agents", Recursive: true},
		{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true},
	}
	for _, p := range []string{
		".claude/settings.json", ".claude/agents", ".claude/agents/a.md",
		".claude-plugin/plugin.json", "plugins/foo/.claude-plugin/plugin.json",
		"README.md", ".claude-evil/plugin.json",
	} {
		if Matches(p, sigs) != MatchesEntry(p, false, sigs) {
			t.Fatalf("Matches(%q) diverged from MatchesEntry(%q, false)", p, p)
		}
	}
}

// The unset and named rows are the controls against a match-everything
// predicate.
func TestSignatureRecursiveRootAnchorIsOptIn(t *testing.T) {
	tests := []struct {
		name string
		sig  Signature
		path string
		want bool
	}{
		{"dot dir owns a root-level file", Signature{Dir: ".", Recursive: true}, "AGENTS.md", true},
		{"dot dir owns a nested descendant", Signature{Dir: ".", Recursive: true}, "a/b/c.md", true},
		{"unset dir stays inert rather than claiming the tree", Signature{Recursive: true}, "AGENTS.md", false},
		{"unset dir stays inert for a descendant too", Signature{Recursive: true}, "a/b/c.md", false},
		{"named dir leaves a sibling of its subtree unowned", Signature{Dir: ".claude", Recursive: true}, "README.md", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Matches(tt.path, []Signature{tt.sig}); got != tt.want {
				t.Fatalf("Matches(%q, %v) = %v, want %v", tt.path, tt.sig, got, tt.want)
			}
		})
	}
}
