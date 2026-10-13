package main

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

var errParentConsulted = errors.New("mask consulted its parent for a path it should have rejected first")

// poisonFS makes a mask that does consult its parent fail loudly, instead of
// passing on a parent that happens to have nothing at the probed path.
type poisonFS struct{}

func (poisonFS) Open(string) (fs.File, error)          { return nil, errParentConsulted }
func (poisonFS) Stat(string) (fs.FileInfo, error)      { return nil, errParentConsulted }
func (poisonFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, errParentConsulted }
func (poisonFS) ReadFile(string) ([]byte, error)       { return nil, errParentConsulted }
func (poisonFS) Lstat(string) (fs.FileInfo, error)     { return nil, errParentConsulted }
func (poisonFS) ReadLink(string) (string, error)       { return "", errParentConsulted }
func (poisonFS) Glob(string) ([]string, error)         { return nil, errParentConsulted }
func (poisonFS) Sub(string) (fs.FS, error)             { return nil, errParentConsulted }

func maskFixture() fstest.MapFS {
	return fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{"hooks":{}}`)},
		".claude/link":          &fstest.MapFile{Data: []byte("settings.json"), Mode: fs.ModeSymlink},
		".claude.json":          &fstest.MapFile{Data: []byte(`{"mcpServers":{}}`)},
		"secret.txt":            &fstest.MapFile{Data: []byte("top secret")},
		"Downloads/clone/x.txt": &fstest.MapFile{Data: []byte("unrelated clone")},
		".claude-evil/x.txt":    &fstest.MapFile{Data: []byte("not the real .claude")},
	}
}

func maskAllowTwoEntries() map[string]bool {
	return map[string]bool{".claude": true, ".claude.json": true}
}

func TestMaskFS_AdmitRequiresAFullPathSegmentNotAPrefix(t *testing.T) {
	m := maskFS{parent: poisonFS{}, allow: maskAllow()}

	_, err := m.Open(".claude-evil/x.txt")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open(%q) error = %v, want fs.ErrNotExist", ".claude-evil/x.txt", err)
	}
}

func maskAllow() map[string]bool { return map[string]bool{".claude": true} }

var invalidPaths = []string{"../x", "/x", ""}

func TestMaskFS_Open(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		f, err := m.Open(".claude/settings.json")
		if err != nil {
			t.Fatalf("Open() error = %v, want nil", err)
		}
		f.Close()
	})
	t.Run("denied", func(t *testing.T) {
		_, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.Open("secret.txt")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Open() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.Open(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("Open(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

func TestMaskFS_Stat(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		info, err := m.Stat(".claude/settings.json")
		if err != nil {
			t.Fatalf("Stat() error = %v, want nil", err)
		}
		if info.Name() != "settings.json" {
			t.Fatalf("Stat().Name() = %q, want %q", info.Name(), "settings.json")
		}
	})
	t.Run("denied", func(t *testing.T) {
		_, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.Stat("secret.txt")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Stat() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.Stat(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("Stat(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

func TestMaskFS_ReadFile(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		data, err := m.ReadFile(".claude/settings.json")
		if err != nil {
			t.Fatalf("ReadFile() error = %v, want nil", err)
		}
		if string(data) != `{"hooks":{}}` {
			t.Fatalf("ReadFile() = %q, want %q", data, `{"hooks":{}}`)
		}
	})
	t.Run("denied", func(t *testing.T) {
		_, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.ReadFile("secret.txt")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("ReadFile() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.ReadFile(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("ReadFile(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

func TestMaskFS_Lstat(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		info, err := m.Lstat(".claude/link")
		if err != nil {
			t.Fatalf("Lstat() error = %v, want nil", err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("Lstat().Mode() = %v, want the symlink bit set", info.Mode())
		}
	})
	t.Run("denied", func(t *testing.T) {
		_, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.Lstat("secret.txt")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Lstat() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.Lstat(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("Lstat(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

func TestMaskFS_ReadLink(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		target, err := m.ReadLink(".claude/link")
		if err != nil {
			t.Fatalf("ReadLink() error = %v, want nil", err)
		}
		if target != "settings.json" {
			t.Fatalf("ReadLink() = %q, want %q", target, "settings.json")
		}
	})
	t.Run("denied", func(t *testing.T) {
		_, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.ReadLink("secret.txt")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("ReadLink() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.ReadLink(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("ReadLink(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

func TestMaskFS_ReadDir(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		entries, err := m.ReadDir(".claude")
		if err != nil {
			t.Fatalf("ReadDir() error = %v, want nil", err)
		}
		if len(entries) != 2 {
			t.Fatalf("ReadDir() len = %d, want 2 (settings.json, link)", len(entries))
		}
	})
	t.Run("denied", func(t *testing.T) {
		_, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.ReadDir("Downloads")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("ReadDir() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.ReadDir(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("ReadDir(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

// The root listing itself never names a denied sibling. Going through
// fs.ReadDir rather than the method directly keeps a dropped forwarder from
// hiding behind the generic fallback, which relists every sibling.
func TestMaskFS_ReadDirDotReturnsOnlyAdmittedEntries(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	entries, err := fs.ReadDir(m, ".")
	if err != nil {
		t.Fatalf("ReadDir(\".\") error = %v, want nil", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	want := map[string]bool{".claude": true}
	if len(got) != len(want) || !got[".claude"] {
		t.Fatalf("ReadDir(\".\") names = %v, want exactly %v", got, want)
	}
}

func TestMaskFS_Glob(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	t.Run("admitted", func(t *testing.T) {
		got, err := m.Glob(".claude/*")
		if err != nil {
			t.Fatalf("Glob() error = %v, want nil", err)
		}
		if len(got) != 2 {
			t.Fatalf("Glob() = %v, want 2 matches under .claude", got)
		}
	})
	t.Run("denied literal never surfaces", func(t *testing.T) {
		got, err := m.Glob("secret.txt")
		if err != nil {
			t.Fatalf("Glob() error = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("Glob() = %v, want no match for a denied sibling", got)
		}
	})
	t.Run("denied literal never consults the parent", func(t *testing.T) {
		got, err := maskFS{parent: poisonFS{}, allow: maskAllow()}.Glob("secret.txt")
		if err != nil {
			t.Fatalf("Glob() error = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("Glob() = %v, want no match for a denied sibling", got)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.Glob(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("Glob(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

func TestMaskFS_GlobStarReturnsOnlyAdmittedResults(t *testing.T) {
	m := maskFS{parent: maskFixture(), allow: maskAllow()}

	got, err := fs.Glob(m, "*")
	if err != nil {
		t.Fatalf("Glob(\"*\") error = %v, want nil", err)
	}
	if len(got) != 1 || got[0] != ".claude" {
		t.Fatalf("Glob(\"*\") = %v, want [\".claude\"]", got)
	}
}

var errCustomSubCalled = errors.New("custom sub called")

type customSubFS struct{ m fstest.MapFS }

func (c customSubFS) Open(name string) (fs.File, error) { return c.m.Open(name) }
func (customSubFS) Sub(string) (fs.FS, error)           { return nil, errCustomSubCalled }

type statAndOpenOnlyFS struct{ m fstest.MapFS }

func (p statAndOpenOnlyFS) Open(name string) (fs.File, error)     { return p.m.Open(name) }
func (p statAndOpenOnlyFS) Stat(name string) (fs.FileInfo, error) { return p.m.Stat(name) }

func TestMaskFS_Sub(t *testing.T) {
	t.Run("admitted delegates to the parent's own SubFS", func(t *testing.T) {
		m := maskFS{parent: customSubFS{m: maskFixture()}, allow: maskAllow()}
		_, err := m.Sub(".claude")
		if !errors.Is(err, errCustomSubCalled) {
			t.Fatalf("Sub() error = %v, want %v", err, errCustomSubCalled)
		}
	})
	t.Run("parent with no SubFS fails loudly", func(t *testing.T) {
		m := maskFS{parent: statAndOpenOnlyFS{m: maskFixture()}, allow: maskAllow()}
		fsys, err := m.Sub(".claude")
		if err == nil {
			t.Fatalf("Sub() = %v, nil, want an error, not a capability-degraded fs.FS", fsys)
		}
	})
	t.Run("denied", func(t *testing.T) {
		m := maskFS{parent: poisonFS{}, allow: maskAllow()}
		_, err := m.Sub("secret.txt")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Sub() error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		poisoned := maskFS{parent: poisonFS{}, allow: maskAllow()}
		for _, p := range invalidPaths {
			_, err := poisoned.Sub(p)
			if !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("Sub(%q) error = %v, want fs.ErrInvalid", p, err)
			}
		}
	})
}

// statOnlyParent poisons Open, so a codepath resolving Stat via Open is
// caught.
type statOnlyParent struct{ m fstest.MapFS }

func (p statOnlyParent) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: errParentConsulted}
}
func (p statOnlyParent) Stat(name string) (fs.FileInfo, error) { return p.m.Stat(name) }

// A poisoned Open is what proves fs.Stat resolved via the parent's own
// StatFS; maskfs.go's forwarder block carries why that matters.
func TestMaskFS_StatPreservesCapabilityThroughAPoisonedOpen(t *testing.T) {
	m := maskFS{parent: statOnlyParent{m: maskFixture()}, allow: maskAllow()}

	if _, err := fs.Stat(m, ".claude"); err != nil {
		t.Fatalf("fs.Stat() error = %v, want nil (Open is poisoned; only Stat is real)", err)
	}
}

type openOnlyFS struct{ fs.FS }

func methodSet(t reflect.Type) map[string]reflect.Method {
	set := make(map[string]reflect.Method, t.NumMethod())
	for i := 0; i < t.NumMethod(); i++ {
		set[t.Method(i).Name] = t.Method(i)
	}
	return set
}

// Gating only ReadDir would still read $HOME/.mcp.json into the global block.
func TestMaskFS_TwoEntryAllowSetContainment(t *testing.T) {
	allow := maskAllowTwoEntries()

	t.Run("admitted: .claude.json reaches the parent", func(t *testing.T) {
		m := maskFS{parent: maskFixture(), allow: allow}
		data, err := m.ReadFile(".claude.json")
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v, want nil", ".claude.json", err)
		}
		if string(data) != `{"mcpServers":{}}` {
			t.Fatalf("ReadFile(%q) = %q, want %q", ".claude.json", data, `{"mcpServers":{}}`)
		}
	})

	denied := []string{
		".mcp.json",
		".claude.jsonx",
		".claudex.json",
		"claude.json",
		"Documents/notes.md",
		"Downloads/clone/.mcp.json",
	}
	for _, p := range denied {
		t.Run("denied without consulting the parent: "+p, func(t *testing.T) {
			_, err := maskFS{parent: poisonFS{}, allow: allow}.ReadFile(p)
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("ReadFile(%q) error = %v, want fs.ErrNotExist", p, err)
			}
		})
	}
}

// maskFS forwards every method fs.Sub's generic wrapper exposes. Comparing
// against the value fs.Sub actually returns catches an io/fs release adding
// an interface a hand-written set would miss silently.
func TestMaskFS_MethodSetMatchesStdlibSubResult(t *testing.T) {
	parent := openOnlyFS{fstest.MapFS{"a": &fstest.MapFile{}}}
	want, err := fs.Sub(parent, "d")
	if err != nil {
		t.Fatalf("fs.Sub() error = %v", err)
	}

	wantSet := methodSet(reflect.TypeOf(want))
	gotSet := methodSet(reflect.TypeOf(maskFS{}))
	for name := range wantSet {
		if _, ok := gotSet[name]; !ok {
			t.Errorf("maskFS has no %s method; fs.Sub's result does", name)
		}
	}

	parentSet := methodSet(reflect.TypeOf(parent))
	added := 0
	for name := range wantSet {
		if _, ok := parentSet[name]; !ok {
			added++
		}
	}
	if added == 0 {
		t.Error("fs.Sub's result adds no method to its Open-only parent, so the loop above would report nothing whatever maskFS dropped")
	}
}

func maskAllowPrefixes() map[string]bool {
	return map[string]bool{
		".claude/settings.json": true,
		".claude/agents":        true,
		".claude.json":          true,
	}
}

func prefixFixture() fstest.MapFS {
	return fstest.MapFS{
		".claude/settings.json":     &fstest.MapFile{Data: []byte(`{"hooks":{}}`)},
		".claude/settings.json.bak": &fstest.MapFile{Data: []byte(`{"hooks":{}}`)},
		".claude/agents/deep/a.md":  &fstest.MapFile{Data: []byte("---\nname: a\n---\n")},
		".claude/projects/t.jsonl":  &fstest.MapFile{Data: []byte("transcript")},
		".claude/debug/log.txt":     &fstest.MapFile{Data: []byte("log")},
		".claude/history.jsonl":     &fstest.MapFile{Data: []byte("history")},
		".claude.json":              &fstest.MapFile{Data: []byte(`{"mcpServers":{}}`)},
		"secret.txt":                &fstest.MapFile{Data: []byte("top secret")},
	}
}

func TestMaskFS_DeclaredPrefixAdmitsItsOwnSubtree(t *testing.T) {
	m := maskFS{parent: prefixFixture(), allow: maskAllowPrefixes()}

	for _, p := range []string{
		".claude/settings.json",
		".claude/agents",
		".claude/agents/deep",
		".claude/agents/deep/a.md",
		".claude.json",
	} {
		if _, err := fs.Stat(m, p); err != nil {
			t.Errorf("Stat(%q) error = %v, want nil", p, err)
		}
	}
}

func TestMaskFS_SiblingsOfADeclaredPrefixAreDenied(t *testing.T) {
	m := maskFS{parent: poisonFS{}, allow: maskAllowPrefixes()}

	for _, p := range []string{
		".claude/projects",
		".claude/projects/t.jsonl",
		".claude/debug",
		".claude/debug/log.txt",
		".claude/history.jsonl",
		".claude/sessions/s.json",
		".claude/settings.json.bak",
		".claude/agentsx/a.md",
		".claude.jsonx",
		"secret.txt",
	} {
		if _, err := m.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want fs.ErrNotExist", p, err)
		}
	}
}

func TestMaskFS_AncestorOfADeclaredPrefixIsAWaypointOnly(t *testing.T) {
	m := maskFS{parent: prefixFixture(), allow: maskAllowPrefixes()}

	entries, err := fs.ReadDir(m, ".claude")
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v, want nil", ".claude", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	if len(got) != 2 || !got["agents"] || !got["settings.json"] {
		t.Fatalf("ReadDir(%q) names = %v, want exactly agents and settings.json", ".claude", got)
	}
}

func TestMaskFS_GlobUnderAnAncestorReturnsOnlyAdmittedResults(t *testing.T) {
	m := maskFS{parent: prefixFixture(), allow: maskAllowPrefixes()}

	got, err := fs.Glob(m, ".claude/*")
	if err != nil {
		t.Fatalf("Glob(%q) error = %v, want nil", ".claude/*", err)
	}
	want := []string{".claude/agents", ".claude/settings.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Glob(%q) = %v, want %v", ".claude/*", got, want)
	}
}

func TestMaskFS_SubRebasesTheDeclaredPrefixes(t *testing.T) {
	m := maskFS{parent: prefixFixture(), allow: maskAllowPrefixes()}

	sub, err := m.Sub(".claude")
	if err != nil {
		t.Fatalf("Sub(%q) error = %v, want nil", ".claude", err)
	}
	if _, err := fs.Stat(sub, "agents/deep/a.md"); err != nil {
		t.Errorf("Stat(%q) on the subtree error = %v, want nil", "agents/deep/a.md", err)
	}
	if _, err := fs.Stat(sub, "projects/t.jsonl"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(%q) on the subtree error = %v, want fs.ErrNotExist", "projects/t.jsonl", err)
	}
}

func TestMaskFS_SubBelowADeclaredPrefixDropsTheMask(t *testing.T) {
	m := maskFS{parent: prefixFixture(), allow: maskAllowPrefixes()}

	sub, err := m.Sub(".claude/agents")
	if err != nil {
		t.Fatalf("Sub(%q) error = %v, want nil", ".claude/agents", err)
	}
	if _, ok := sub.(maskFS); ok {
		t.Fatalf("Sub(%q) = %T, want the parent's own subtree", ".claude/agents", sub)
	}
	if _, err := fs.Stat(sub, "deep/a.md"); err != nil {
		t.Errorf("Stat(%q) on the subtree error = %v, want nil", "deep/a.md", err)
	}
}
