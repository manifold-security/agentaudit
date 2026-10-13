package finding

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// internal/ir is the one intra-module import this package may take, for the
// Entity a Capability carries. Reaching any further — adapter above all — is
// what would force Finding.Agent to stop being a plain string.
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
			if path == "io/fs" ||
				strings.HasPrefix(path, "github.com/manifold-security/agentaudit/") || strings.Contains(path, ".") {
				t.Fatalf("%s imports forbidden package %q", file, path)
			}
		}
	}

	if inspected == 0 {
		t.Fatal("no non-test source files inspected; this guard proved nothing")
	}
}
