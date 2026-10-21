package treefs

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// treefs's non-test files import the standard library alone; a dot in an
// import path's first element marks one that is not.
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
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Fatalf("%s imports non-stdlib package %q", file, path)
			}
		}
	}

	if inspected == 0 {
		t.Fatal("no non-test source files inspected; this guard proved nothing")
	}
}
