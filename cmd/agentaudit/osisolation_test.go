package main

import (
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/manifold-security/agentaudit"

// cliPackage may reach the OS or a third-party CLI framework.
const cliPackage = modulePath + "/cmd/agentaudit"

const remotePackage = modulePath + "/remote"

// frontendAllowances names, per frontend, the forbiddenImports tokens that
// frontend may reach. A frontend carries the module's boundary to a host, so
// it is allowed what that host costs and nothing beyond.
var frontendAllowances = map[string][]string{
	cliPackage:    forbiddenImports,
	remotePackage: {"os", "net", "syscall", "path/filepath"},
}

// permitted reports whether imp is one of tokens or a subpackage of one:
// os/exec carries the reach of os, so an exact match would let it walk past.
func permitted(imp string, tokens []string) bool {
	for _, token := range tokens {
		if imp == token || strings.HasPrefix(imp, token+"/") {
			return true
		}
	}
	return false
}

// yamlPackages enumerates the packages allowed to import yamlV3Import:
// yamlconf parses YAML, and an adapter that walks the node tree it returns
// needs the decoder's types too.
var yamlPackages = []string{
	modulePath + "/internal/adapters/claude",
	modulePath + "/internal/yamlconf",
}

const yamlV3Import = "gopkg.in/yaml.v3"

// tomlPackages enumerates the packages allowed to import tomlImport. One
// wrapper holds it, so no adapter names the decoder at all.
var tomlPackages = []string{
	modulePath + "/internal/tomlconf",
}

const tomlImport = "github.com/pelletier/go-toml/v2"

var gogitPackages = []string{remotePackage}

const gogitModule = "github.com/go-git/go-git/v5"

// forbiddenImports are the tokens no package outside frontends may reach.
var forbiddenImports = []string{"os", "net", "syscall", "path/filepath", "github.com/spf13/cobra"}

// enumerationFloor guards against a truncated go list passing the sweep.
var enumerationFloor = []string{
	modulePath + "/adapter",
	modulePath + "/internal/discovery",
	modulePath + "/internal/ir",
	modulePath + "/internal/report/json",
	modulePath + "/internal/report/md",
	modulePath + "/internal/report/pretty",
	modulePath + "/internal/tomlconf",
	remotePackage,
}

// listFormat's first field is the package: no import path contains a space.
const listFormat = `{{.ImportPath}} {{join .Imports " "}}`

// listGraph maps each package to its direct imports. go list reads non-test
// GoFiles only, so a test file's own import — the pretty reporter reaches for
// os to read its goldens — stays out of the graph and out of every claim
// below. GOPROXY=off keeps the call offline, so the module cache must already
// hold the whole build list: go list loads every module go.mod requires,
// including ones this platform never imports, and building this binary does
// not fetch those. .github/workflows/ci.yml runs go mod download for that
// reason.
func listGraph(t *testing.T) map[string][]string {
	t.Helper()

	cmd := exec.Command("go", "list", "-mod=readonly", "-deps", "-f", listFormat, modulePath+"/...")
	cmd.Env = append(os.Environ(), "GOPROXY=off")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s/... error = %v\nstderr:\n%s", modulePath, err, stderr.String())
	}

	graph := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		graph[fields[0]] = fields[1:]
	}
	if len(graph) == 0 {
		t.Fatalf("go list -deps %s/... listed no package; an empty listing must not pass any check below silently", modulePath)
	}
	return graph
}

func forbidden(imp string) bool {
	return permitted(imp, forbiddenImports)
}

func firstParty(pkg string) bool {
	return pkg == modulePath || strings.HasPrefix(pkg, modulePath+"/")
}

// thirdParty reports whether pkg comes from another module: a stdlib path
// carries no dot in its first segment.
func thirdParty(pkg string) bool {
	if firstParty(pkg) {
		return false
	}
	first, _, _ := strings.Cut(pkg, "/")
	return strings.Contains(first, ".")
}

// reach walks pkg's first- and third-party imports transitively. Stdlib
// edges stop the walk on purpose: fmt itself imports os, so following them
// would make every package look like a violation and prove nothing.
func reach(graph map[string][]string, pkg string) []string {
	seen := map[string]bool{pkg: true}
	order := []string{pkg}
	for i := 0; i < len(order); i++ {
		for _, imp := range graph[order[i]] {
			if seen[imp] || (!firstParty(imp) && !thirdParty(imp)) {
				continue
			}
			seen[imp] = true
			order = append(order, imp)
		}
	}
	return order
}

// No package this module owns reaches a forbiddenImports token its
// frontendAllowances entry does not name, through its own imports or the
// first- and third-party packages they lead to, and none imports a confined
// dependency its list does not name. Enumerating from go list is what makes
// that hold for a package added later.
func TestOSIsolation_EngineAndReporterPackages(t *testing.T) {
	sweep(t, listGraph(t))
}

func sweep(t *testing.T, graph map[string][]string) {
	t.Helper()

	var guarded []string
	for pkg := range graph {
		if firstParty(pkg) {
			guarded = append(guarded, pkg)
		}
	}
	if len(guarded) == 0 {
		t.Fatalf("go list enumerated no %s package to check", modulePath)
	}
	sort.Strings(guarded)

	for _, want := range enumerationFloor {
		if _, ok := graph[want]; !ok {
			t.Fatalf("go list did not enumerate %s; it listed %v", want, guarded)
		}
	}

	for _, pkg := range guarded {
		if !slices.Contains(yamlPackages, pkg) {
			for _, imp := range graph[pkg] {
				if imp == yamlV3Import {
					t.Fatalf("%s imports %q, which is confined to %v", pkg, yamlV3Import, yamlPackages)
				}
			}
		}
		if !slices.Contains(tomlPackages, pkg) {
			for _, imp := range graph[pkg] {
				if imp == tomlImport {
					t.Fatalf("%s imports %q, which is confined to %v", pkg, tomlImport, tomlPackages)
				}
			}
		}
		if !slices.Contains(gogitPackages, pkg) {
			for _, imp := range graph[pkg] {
				if permitted(imp, []string{gogitModule}) {
					t.Fatalf("%s imports %q, which is confined to %v", pkg, imp, gogitPackages)
				}
			}
		}
		allowed := frontendAllowances[pkg]
		for _, dep := range reach(graph, pkg) {
			for _, imp := range graph[dep] {
				if !forbidden(imp) || permitted(imp, allowed) {
					continue
				}
				if dep == pkg {
					t.Fatalf("%s imports %q, which is forbidden outside a frontend", pkg, imp)
				}
				t.Fatalf("%s reaches %s, which imports %q, forbidden outside a frontend", pkg, dep, imp)
			}
		}
	}
}

// Each package the allowance names reaches the decoder, so the allowance
// describes a dependency that is really there rather than widening the
// sweep's exception for nothing.
func TestOSIsolation_EveryYAMLPackageImportsYAMLv3(t *testing.T) {
	if len(yamlPackages) == 0 {
		t.Fatal("yamlPackages is empty; this guard would check nothing")
	}

	for _, pkg := range yamlPackages {
		t.Run(pkg, func(t *testing.T) {
			imports := packageImports(t, pkg)

			found := false
			for _, imp := range imports {
				if imp == yamlV3Import {
					found = true
				}
				if forbidden(imp) {
					t.Fatalf("%s imports %q, which is forbidden outside a frontend", pkg, imp)
				}
			}
			if !found {
				t.Fatalf("%s Imports = %v, want it to include %q", pkg, imports, yamlV3Import)
			}
		})
	}
}

func TestOSIsolation_EveryTOMLPackageImportsTheTOMLDecoder(t *testing.T) {
	if len(tomlPackages) == 0 {
		t.Fatal("tomlPackages is empty; this guard would check nothing")
	}

	for _, pkg := range tomlPackages {
		t.Run(pkg, func(t *testing.T) {
			imports := packageImports(t, pkg)

			found := false
			for _, imp := range imports {
				if imp == tomlImport {
					found = true
				}
				if forbidden(imp) {
					t.Fatalf("%s imports %q, which is forbidden outside a frontend", pkg, imp)
				}
			}
			if !found {
				t.Fatalf("%s Imports = %v, want it to include %q", pkg, imports, tomlImport)
			}
		})
	}
}

// The boundary applies to every package but a frontend, not project-wide.
// This also shows the graph can see a forbidden import when one is there,
// so the sweep above is not passing on a listing it failed to read.
func TestOSIsolation_CLIMayImportOSAndCobra(t *testing.T) {
	imports := packageImports(t, cliPackage)

	for _, want := range []string{"os", "github.com/spf13/cobra"} {
		found := false
		for _, imp := range imports {
			if imp == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s Imports = %v, want it to include %q", cliPackage, imports, want)
		}
	}
}

// path/filepath is forbidden behind the fs.FS boundary and stays available
// to cliPackage: it does host filesystem I/O — EvalSymlinks, Walk and Glob
// reach the real disk — so a guarded package taking it leaves that boundary
// as os does. Bare path is string handling with no I/O and the packages that
// build fs.FS names use it, so forbidding the shorter prefix would take the
// boundary's own tool away.
func TestOSIsolation_ForbidsPathFilepathOutsideAFrontend(t *testing.T) {
	const filepathImport = "path/filepath"

	if !forbidden(filepathImport) {
		t.Fatalf("forbidden(%q) = false, want true; the sweep rejects what forbiddenImports names", filepathImport)
	}
	if forbidden("path") {
		t.Fatalf("forbidden(%q) = true, want false", "path")
	}

	imports := packageImports(t, cliPackage)
	for _, imp := range imports {
		if imp == filepathImport {
			return
		}
	}
	t.Fatalf("%s Imports = %v, want it to include %q", cliPackage, imports, filepathImport)
}

// remote reaches every token its allowance names, so no token in it widens
// the sweep's exception for nothing.
func TestOSIsolation_RemoteReachesEveryTokenItsAllowanceNames(t *testing.T) {
	graph := listGraph(t)
	allowed := frontendAllowances[remotePackage]
	if len(allowed) == 0 {
		t.Fatalf("frontendAllowances[%s] is empty; this guard would check nothing", remotePackage)
	}
	for _, token := range allowed {
		reached := false
		for _, dep := range reach(graph, remotePackage) {
			for _, imp := range graph[dep] {
				if permitted(imp, []string{token}) {
					reached = true
				}
			}
		}
		if !reached {
			t.Fatalf("%s reaches no package under %q, which its allowance names", remotePackage, token)
		}
	}
}

// remote's own non-test code imports no forbidden package but net/http.
// The allowance admits os for go-git's sake, so the sweep would pass an os
// import here.
func TestOSIsolation_RemoteImportsGoGitAndNoOtherForbiddenPackageThanNetHTTP(t *testing.T) {
	const netHTTP = "net/http"
	imports := packageImports(t, remotePackage)

	viaGoGit, viaHTTP := false, false
	for _, imp := range imports {
		switch {
		case permitted(imp, []string{gogitModule}):
			viaGoGit = true
		case imp == netHTTP:
			viaHTTP = true
		case forbidden(imp):
			t.Fatalf("%s imports %q; its only forbidden direct import is %q", remotePackage, imp, netHTTP)
		}
	}
	if !viaGoGit || !viaHTTP {
		t.Fatalf("%s Imports = %v, want it to include %q and a package under %q", remotePackage, imports, netHTTP, gogitModule)
	}
}

func packageImports(t *testing.T, pkg string) []string {
	t.Helper()

	graph := listGraph(t)
	imports, ok := graph[pkg]
	if !ok {
		t.Fatalf("go list did not enumerate %s", pkg)
	}
	if len(imports) == 0 {
		t.Fatalf("go list reported no import for %s; an empty import set must not pass silently", pkg)
	}
	return imports
}
