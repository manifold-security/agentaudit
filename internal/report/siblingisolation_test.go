package report_test

import (
	"go/build"
	"testing"
)

var reporterDirs = []string{
	"pretty",
	"json",
	"md",
}

// Every reporter couples to Describe/Digest only through this shared parent
// package, never through a shortcut sibling import.
func TestReporterPackagesStaySiblingIndependent(t *testing.T) {
	for _, dir := range reporterDirs {
		pkg, err := build.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("build.ImportDir(%q) error = %v", dir, err)
		}
		if len(pkg.GoFiles) == 0 {
			t.Fatalf("%s has no scanned .go source files; a stale or mistyped reporterDirs entry would silently skip its import check", dir)
		}
		for _, imp := range pkg.Imports {
			for _, sibling := range reporterDirs {
				if sibling == dir {
					continue
				}
				if imp == "github.com/manifold-security/agentaudit/internal/report/"+sibling {
					t.Fatalf("%s imports %s, a sibling reporter package", dir, sibling)
				}
			}
		}
	}
}
