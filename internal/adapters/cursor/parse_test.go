package cursor

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// degradedCursorSources overrides what a source degrades to. A malformed
// body leaves a parser that classifies an entry by its type untouched, so
// its degraded form is an entry the scanner refuses to open.
var degradedCursorSources = map[string]*fstest.MapFile{
	".cursor/hooks/bootstrap.sh": {Mode: fs.ModeSymlink, Data: []byte("../../offtree.sh")},
}

// Cross-checked against the probe table so an override a renamed probe left
// behind fails by name, rather than quietly overriding nothing.
func TestDegradedCursorSourcesOverrideAProbedPath(t *testing.T) {
	probed := map[string]bool{}
	for _, p := range signatureProbes {
		probed[p.path] = true
	}
	for file := range degradedCursorSources {
		if !probed[file] {
			t.Errorf("degradedCursorSources overrides %q, which signatureProbes no longer declares", file)
		}
	}
}

// One degraded source must not take its siblings with it. Dropping a whole
// surface because a neighbour failed prints a clean bill of health over
// configuration nothing read, which is worse than reporting nothing at all.
func TestParseKeepsEverySourceWhenOneDegrades(t *testing.T) {
	const malformed = `{"`

	for _, degraded := range signatureProbes {
		t.Run(degraded.path, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for _, p := range signatureProbes {
				for file, body := range p.beside {
					fsys[file] = &fstest.MapFile{Data: []byte(body)}
				}
				if p.path != degraded.path {
					fsys[p.path] = &fstest.MapFile{Data: []byte(p.body)}
					continue
				}
				if entry, override := degradedCursorSources[p.path]; override {
					fsys[p.path] = entry
					continue
				}
				fsys[p.path] = &fstest.MapFile{Data: []byte(malformed)}
			}

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil: a malformed source degrades", err)
			}

			if len(warnings) != 1 || warnings[0].File != degraded.path {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, degraded.path)
			}

			seen := map[string]bool{}
			for _, e := range entities {
				seen[ir.LocationOf(e).File] = true
			}
			for _, p := range signatureProbes {
				if p.path == degraded.path {
					continue
				}
				if !seen[p.locatedFile()] {
					t.Errorf("%q contributed no entity; it outlives the %q warning", p.path, degraded.path)
				}
			}
			if seen[degraded.locatedFile()] {
				t.Errorf("%q contributed an entity despite degrading", degraded.path)
			}
		})
	}
}
