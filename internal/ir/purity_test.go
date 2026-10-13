package ir

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The frozen contract stays isolated: every package above binds to these
// names, so an import here would let a change anywhere else reach the entities
// the whole engine matches against.
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
			if path == "io/fs" ||
				strings.HasPrefix(path, "github.com/manifold-security/agentaudit/") ||
				strings.HasPrefix(path, "encoding/") ||
				strings.Contains(path, ".") {
				t.Fatalf("%s imports forbidden package %q", file, path)
			}
		}
	}

	if inspected == 0 {
		t.Fatal("no non-test source files inspected; this guard proved nothing")
	}
}
