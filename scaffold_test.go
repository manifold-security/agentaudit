package agentaudit_test

import (
	"os"
	"path/filepath"
	"testing"
)

// scaffoldPaths is checked against the real working directory: the layout
// under test is this repository's own, so there is no fs.FS to inject.
var scaffoldPaths = []string{
	"go.mod",
	"agentaudit.go",
	"cmd/agentaudit/main.go",
	"finding",
	"finding/doc.go",
	"adapter",
	"adapter/doc.go",
	"internal/ir",
	"internal/ir/doc.go",
	"internal/discovery",
	"internal/discovery/doc.go",
	"internal/adapters/claude",
	"internal/adapters/claude/doc.go",
	"internal/adapters/cursor",
	"internal/adapters/cursor/doc.go",
	"internal/ruleeng",
	"internal/ruleeng/doc.go",
	"internal/registry",
	"internal/registry/doc.go",
	"internal/report",
	"internal/report/doc.go",
	"rules/claude",
	"rules/cursor",
	"testdata/benign",
	"testdata/malicious",
}

func TestScaffoldMatchesArchitecture(t *testing.T) {
	for _, p := range scaffoldPaths {
		if _, err := os.Stat(filepath.FromSlash(p)); err != nil {
			t.Errorf("scaffold path %q missing: %v", p, err)
		}
	}
}
