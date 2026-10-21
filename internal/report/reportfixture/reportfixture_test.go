package reportfixture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// Every Kind-prefixed constant declared anywhere in internal/ir is emitted
// by at least one Report() finding.
func TestReportCoversEveryIRKind(t *testing.T) {
	declared := irKindConstants(t)

	emitted := make(map[string]bool, len(declared))
	for _, f := range Report().Findings() {
		emitted[f.Capability.Entity.Kind()] = true
	}

	for _, kind := range declared {
		if !emitted[kind] {
			t.Errorf("ir declares Kind %q with no reportfixture.Report() finding emitting it", kind)
		}
	}
}

// Report() carries an ir.Sandbox finding on each side of Identity()'s own
// SocketPath branch.
func TestReportCoversBothSandboxIdentityBranches(t *testing.T) {
	var sawSocketForm, sawGrantForm bool
	for _, f := range Report().Findings() {
		sandbox, ok := f.Capability.Entity.(ir.Sandbox)
		if !ok {
			continue
		}
		if sandbox.SocketPath != "" {
			sawSocketForm = true
			continue
		}
		sawGrantForm = true
	}
	if !sawSocketForm || !sawGrantForm {
		t.Fatalf("Report() sandbox coverage: socket-path branch=%v, mode/path/access branch=%v, want both", sawSocketForm, sawGrantForm)
	}
}

func irKindConstants(t *testing.T) []string {
	t.Helper()

	dir := path.Join("..", "..", "ir")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var kinds []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		kinds = append(kinds, kindConstantsInFile(t, name, file)...)
	}

	if len(kinds) == 0 {
		t.Fatal("parsed zero Kind constants from internal/ir; this guard proved nothing")
	}
	return kinds
}

func kindConstantsInFile(t *testing.T, filename string, file *ast.File) []string {
	t.Helper()

	var kinds []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if !strings.HasPrefix(ident.Name, "Kind") {
					continue
				}
				if i >= len(vs.Values) {
					t.Fatalf("%s: %s declares no literal value", filename, ident.Name)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s: %s is not a plain string literal", filename, ident.Name)
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: unquote %s: %v", filename, lit.Value, err)
				}
				kinds = append(kinds, unquoted)
			}
		}
	}
	return kinds
}
