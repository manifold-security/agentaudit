package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestResolveTargets(t *testing.T) {
	tests := []struct {
		name       string
		positional []string
		scanDirs   []string
		want       []string
	}{
		{"no input defaults to the current directory", nil, nil, []string{"."}},
		{"positional only", []string{"x"}, nil, []string{"x"}},
		{"scan-dir only, no implicit dot", nil, []string{"x"}, []string{"x"}},
		{"positional and scan-dir unioned in order", []string{"x"}, []string{"y"}, []string{"x", "y"}},
		{"positional duplicated by scan-dir collapses", []string{"x"}, []string{"x"}, []string{"x"}},
		{"scan-dir with a leading-dot spelling collapses", []string{"x"}, []string{"./x"}, []string{"x"}},
		{"scan-dir with a trailing slash collapses", []string{"x"}, []string{"x/"}, []string{"x"}},
		{"repeated identical scan-dir values collapse", nil, []string{"y", "y"}, []string{"y"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveTargets(tt.positional, tt.scanDirs)
			if err != nil {
				t.Fatalf("resolveTargets(%v, %v) error = %v, want nil", tt.positional, tt.scanDirs, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("resolveTargets(%v, %v) = %v, want %v", tt.positional, tt.scanDirs, got, tt.want)
			}
		})
	}
}

func TestResolveTargets_EmptyScanDirValueIsAUsageFault(t *testing.T) {
	_, err := resolveTargets(nil, []string{""})
	if err == nil {
		t.Fatalf("resolveTargets(nil, [\"\"]) error = nil, want a usage error")
	}
	if got := err.Error(); !strings.HasPrefix(got, "agentaudit:") {
		t.Fatalf("resolveTargets error = %q, want it prefixed with %q", got, "agentaudit:")
	}
}

// Drives run() through the real Cobra/pflag layer resolveTargets never sees.
func TestRun_ScanDirEmptyValueExits2(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"bare empty value", []string{"--scan-dir", ""}},
		{"equals-form empty value", []string{"--scan-dir="}},
		{"positional plus empty value", []string{"x", "--scan-dir", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != 2 {
				t.Fatalf("run(%v) = %d, want 2\nstdout: %s\nstderr: %s", tt.args, got, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRun_EmptyPositionalPathExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{""}, &stdout, &stderr); got != 2 {
		t.Fatalf("run([\"\"]) = %d, want 2\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
}

func openRootDeclNames(t *testing.T) []string {
	t.Helper()
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error = %v", err)
	}

	callsOpenRoot := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkgIdent.Name == "os" && sel.Sel.Name == "OpenRoot" {
				found = true
			}
			return true
		})
		return found
	}

	fset := token.NewFileSet()
	var names []string
	for _, name := range entries {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", name, err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if callsOpenRoot(d) {
					names = append(names, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, ident := range value.Names {
						if i < len(value.Values) && callsOpenRoot(value.Values[i]) {
							names = append(names, ident.Name)
						}
					}
				}
			}
		}
	}
	return names
}

// Asserting WHICH declaration calls os.OpenRoot, not merely how many calls
// exist, also catches relocating the call out of openTarget.
func TestOpenTargetIsTheOnlyOpenRootCallSite(t *testing.T) {
	want := []string{"openTarget"}
	if got := openRootDeclNames(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("declarations calling os.OpenRoot in cmd/agentaudit = %v, want %v", got, want)
	}
}

// A finding sourced from an in-memory FS proves openTarget is the only seam
// between a target path and the fs.FS the real scan runs against.
func TestOpenTarget_IsTheOnlyRouteFromPathToFS(t *testing.T) {
	original := openTarget
	openTarget = func(path string) (fs.FS, func() error, error) {
		if path != "anything" {
			t.Fatalf("openTarget path = %q, want the target run() was given", path)
		}
		return fstest.MapFS{
			".mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)},
		}, func() error { return nil }, nil
	}
	t.Cleanup(func() { openTarget = original })

	var stdout, stderr bytes.Buffer
	if got := run([]string{"anything"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
}
