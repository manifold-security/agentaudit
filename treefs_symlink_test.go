package agentaudit_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/treefs"
)

var symlinkRowSettings = hookSettingsJSON("audit.sh")

func TestSymlinkResolutionMatchesOSRoot(t *testing.T) {
	tests := []symlinkRow{
		chainRow(1, true),
		chainRow(7, true),
		chainRow(8, true),
		chainRow(9, false),
		chainRow(12, false),
		{
			name:  "link in an intermediate component of a target",
			links: map[string]string{".claude": "real/cfg", "real": "store"},
			files: map[string]string{"store/cfg/settings.json": symlinkRowSettings},
			reads: true,
		},
		{
			name:    "escaping",
			links:   map[string]string{".claude": "../outside"},
			outside: map[string]string{"outside/settings.json": symlinkRowSettings},
			refused: true,
		},
		{
			name:    "absolute",
			links:   map[string]string{".claude": "/nonexistent/cfg"},
			refused: true,
		},
		{
			name:    "loop",
			links:   map[string]string{"a": "b", "b": "a"},
			files:   map[string]string{".claude/settings.json": symlinkRowSettings},
			reads:   true,
			refused: true,
		},
		{
			name:  "dot-dot after a link",
			links: map[string]string{".claude": "decoy/../hidden", "decoy": "a/b"},
			files: map[string]string{
				"hidden/settings.json":   "{}",
				"a/hidden/settings.json": symlinkRowSettings,
				"a/b/x":                  "",
			},
			reads: true,
		},
		{
			name:    "a file as an intermediate component",
			links:   map[string]string{".claude": "real.json/cfg"},
			files:   map[string]string{"real.json": symlinkRowSettings},
			refused: true,
		},
		{
			name:  "a file link",
			links: map[string]string{".mcp.json": "real.json"},
			files: map[string]string{"real.json": sealMCPJSON},
			reads: true,
		},
		{
			name:    "a trailing slash after a file link",
			links:   map[string]string{".mcp.json": "real.json/"},
			files:   map[string]string{"real.json": sealMCPJSON},
			refused: true,
		},
		{
			name:  "dangling",
			links: map[string]string{".claude": "missing"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			writeFiles(t, root, tt.files)
			writeFiles(t, base, tt.outside)
			for link, target := range tt.links {
				if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(link))); err != nil {
					t.Fatalf("os.Symlink(%q, %q) error = %v", target, link, err)
				}
			}

			report := plainParity(t, root)
			if got := len(report.Findings()) > 0; got != tt.reads {
				t.Fatalf("os.Root findings = %d, want reads = %v", len(report.Findings()), tt.reads)
			}
			if got := report.UnreadableSources() > 0; got != tt.refused {
				t.Fatalf("os.Root UnreadableSources() = %d, want refused = %v", report.UnreadableSources(), tt.refused)
			}
			recursiveParity(t, root)
		})
	}
}

func TestScanCountsAMalformedLinkTargetAsUnreadable(t *testing.T) {
	scan := func(target string) agentaudit.Report {
		tree := newTree(t, []treefs.Entry{
			{Path: ".claude", Mode: fs.ModeSymlink | 0o777},
			{Path: "real/settings.json", Mode: 0o644},
		}, map[string]string{".claude": target, "real/settings.json": symlinkRowSettings}, "")
		tree.Seal()
		return plainScan(t, agentaudit.New(), tree)
	}
	if report := scan("real"); len(report.Findings()) == 0 {
		t.Fatal("no finding through .claude -> real; the counts below would prove nothing")
	}
	for name, target := range map[string]string{
		"NUL":                    "real\x00/x",
		"longer than 4096 bytes": strings.Repeat("./", 2049) + "real",
	} {
		t.Run(name, func(t *testing.T) {
			if got := scan(target).UnreadableSources(); got != 1 {
				t.Fatalf("UnreadableSources() = %d, want 1", got)
			}
		})
	}
}

type symlinkRow struct {
	name           string
	links          map[string]string
	files          map[string]string
	outside        map[string]string
	reads, refused bool
}

func chainRow(n int, reads bool) symlinkRow {
	links := map[string]string{}
	from := ".claude"
	for i := 1; i < n; i++ {
		next := fmt.Sprintf("l%d", i)
		links[from] = next
		from = next
	}
	links[from] = "real/cfg"
	return symlinkRow{
		name:    fmt.Sprintf("chain of %d links", n),
		links:   links,
		files:   map[string]string{"real/cfg/settings.json": symlinkRowSettings},
		reads:   reads,
		refused: !reads,
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()

	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", root, err)
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("os.MkdirAll(%q) error = %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", p, err)
		}
	}
}
