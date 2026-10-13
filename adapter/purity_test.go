package adapter

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The port reaches down to internal/ir for the entities Parse returns, never
// up to finding. An adapter that could see a Finding would decide what its own
// output means, which is the rule engine's job.
func TestPackagePurity(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	fset := token.NewFileSet()
	inspected := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		inspected++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "github.com/manifold-security/agentaudit/internal/ir" {
				continue
			}
			if strings.HasPrefix(path, "github.com/manifold-security/agentaudit/") || strings.Contains(path, ".") {
				t.Fatalf("%s imports forbidden package %q", file, path)
			}
		}
	}

	if inspected == 0 {
		t.Fatal("no non-test source files inspected; this guard proved nothing")
	}
}
