package agentaudit_test

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/treefs"
)

const sealMCPJSON = `{"mcpServers":{"x":{"command":"npx"}}}`

func TestSealCountsAWithheldBlobAsUnreadable(t *testing.T) {
	tests := []struct {
		name     string
		entries  []treefs.Entry
		blobs    map[string]string
		withheld string
	}{
		{
			name:     "regular file",
			entries:  sealEntries(treefs.Entry{Path: ".mcp.json", Mode: 0o644}),
			blobs:    sealBlobs(map[string]string{".mcp.json": sealMCPJSON}),
			withheld: ".mcp.json",
		},
		{
			name: "file symlink",
			entries: sealEntries(
				treefs.Entry{Path: ".mcp.json", Mode: fs.ModeSymlink | 0o777},
				treefs.Entry{Path: "real.json", Mode: 0o644},
			),
			blobs:    sealBlobs(map[string]string{".mcp.json": "real.json", "real.json": sealMCPJSON}),
			withheld: ".mcp.json",
		},
		{
			name: "directory symlink",
			entries: []treefs.Entry{
				{Path: ".claude", Mode: fs.ModeSymlink | 0o777},
				{Path: "real/cfg/settings.json", Mode: 0o644},
			},
			blobs: map[string]string{
				".claude":                "real/cfg",
				"real/cfg/settings.json": hookSettingsJSON("audit.sh"),
			},
			withheld: ".claude",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnings []error
			s := agentaudit.New(agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }))
			tree := newTree(t, tt.entries, tt.blobs, tt.withheld)
			if asked := selectRound(t, s, tree); !slices.Equal(asked, []string{tt.withheld}) {
				t.Fatalf("Select() = %q, want [%q]", asked, tt.withheld)
			}
			tree.Seal()

			report := plainScan(t, s, tree)
			if got := report.UnreadableSources(); got != 1 {
				t.Fatalf("UnreadableSources() = %d, want 1", got)
			}
			if !slices.ContainsFunc(warnings, func(err error) bool { return strings.Contains(err.Error(), tt.withheld) }) {
				t.Fatalf("warnings = %v, want one naming %q", warnings, tt.withheld)
			}
		})
	}
}

func TestSealOfAnUploadReportsAllButTheRefusedBlob(t *testing.T) {
	entries := sealEntries(treefs.Entry{Path: ".mcp.json", Mode: 0o644})
	blobs := sealBlobs(map[string]string{".mcp.json": sealMCPJSON})

	whole := newTree(t, entries, blobs, "")
	whole.Seal()
	if files := findingFiles(plainScan(t, agentaudit.New(), whole)); !slices.Contains(files, ".mcp.json") {
		t.Fatalf("findings come from %v with every blob held, want one from .mcp.json; its absence below would prove nothing", files)
	}

	tree := newTree(t, entries, blobs, ".mcp.json")
	tree.Seal()
	report := plainScan(t, agentaudit.New(), tree)
	files := findingFiles(report)
	if slices.Contains(files, ".mcp.json") {
		t.Fatalf("findings come from %v, want none from the refused .mcp.json", files)
	}
	if !slices.Contains(files, ".claude/settings.json") {
		t.Fatalf("findings come from %v, want the hook in .claude/settings.json", files)
	}
	if got := report.UnreadableSources(); got != 1 {
		t.Fatalf("UnreadableSources() = %d, want 1", got)
	}
}

func findingFiles(report agentaudit.Report) []string {
	var files []string
	for _, f := range report.Findings() {
		files = append(files, f.Capability.Provenance.File)
	}
	return files
}

func sealEntries(extra ...treefs.Entry) []treefs.Entry {
	return append([]treefs.Entry{{Path: ".claude/settings.json", Mode: 0o644}}, extra...)
}

func sealBlobs(extra map[string]string) map[string]string {
	blobs := map[string]string{".claude/settings.json": hookSettingsJSON("audit.sh")}
	for p, data := range extra {
		blobs[p] = data
	}
	return blobs
}

func newTree(t *testing.T, entries []treefs.Entry, blobs map[string]string, withheld string) *treefs.FS {
	t.Helper()

	tree, err := treefs.New(entries, func(p string) ([]byte, bool) {
		data, ok := blobs[p]
		return []byte(data), ok && p != withheld
	})
	if err != nil {
		t.Fatalf("treefs.New() error = %v", err)
	}
	return tree
}
