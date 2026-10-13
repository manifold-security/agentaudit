package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
)

const linkHookSettings = `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify.sh"}]}]}}`

// canonicalDir strips the symlinked prefix macOS gives /var, without which
// every rebase below would miss for a reason unrelated to the code.
func canonicalDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(t.TempDir()) error = %v", err)
	}
	return dir
}

func openRoots(t *testing.T, dir string) (linkFS, fs.FS) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%s) error = %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return newLinkFS(root.FS(), dir), root.FS()
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", dir, err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
}

func mustRefuseRaw(t *testing.T, raw fs.FS, name string) {
	t.Helper()
	if _, err := fs.Stat(raw, name); err == nil {
		t.Fatalf("the raw containment root already resolves %q, so this fixture exercises nothing", name)
	}
}

func TestLinkFS_AbsoluteInRootDirectorySymlinkResolves(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, "config"))
	writeFile(t, filepath.Join(root, "config", "settings.json"), linkHookSettings)
	link(t, filepath.Join(root, "config"), filepath.Join(root, ".claude"))

	lfs, raw := openRoots(t, root)
	mustRefuseRaw(t, raw, ".claude")

	info, err := fs.Stat(lfs, ".claude")
	if err != nil {
		t.Fatalf("Stat(.claude) error = %v, want the in-root target followed", err)
	}
	if !info.IsDir() {
		t.Fatalf("Stat(.claude).IsDir() = false, want the directory behind the link")
	}

	entries, err := fs.ReadDir(lfs, ".claude")
	if err != nil {
		t.Fatalf("ReadDir(.claude) error = %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{"settings.json"}) {
		t.Fatalf("ReadDir(.claude) names = %v, want [settings.json]", names)
	}

	data, err := fs.ReadFile(lfs, ".claude/settings.json")
	if err != nil {
		t.Fatalf("ReadFile(.claude/settings.json) error = %v", err)
	}
	if string(data) != linkHookSettings {
		t.Fatalf("ReadFile(.claude/settings.json) = %q, want the target's own bytes", data)
	}
}

func TestLinkFS_AbsoluteInRootFileSymlinkResolves(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, ".claude"))
	mkdirAll(t, filepath.Join(root, "real"))
	writeFile(t, filepath.Join(root, "real", "settings.json"), linkHookSettings)
	link(t, filepath.Join(root, "real", "settings.json"), filepath.Join(root, ".claude", "settings.json"))

	lfs, raw := openRoots(t, root)
	mustRefuseRaw(t, raw, ".claude/settings.json")

	data, err := fs.ReadFile(lfs, ".claude/settings.json")
	if err != nil {
		t.Fatalf("ReadFile(.claude/settings.json) error = %v, want the in-root target followed", err)
	}
	if string(data) != linkHookSettings {
		t.Fatalf("ReadFile(.claude/settings.json) = %q, want the target's own bytes", data)
	}
}

// Widening the rewrite past a faithful in-root spelling turns one of these
// fixtures RED.
func TestLinkFS_RefusedTargetsStayRefused(t *testing.T) {
	tests := []struct {
		name  string
		probe string
		build func(t *testing.T, parent string) string
	}{
		{
			name:  "an absolute target outside the root",
			probe: ".claude",
			build: func(t *testing.T, parent string) string {
				outside := filepath.Join(parent, "outside")
				mkdirAll(t, outside)
				writeFile(t, filepath.Join(outside, "settings.json"), linkHookSettings)
				root := filepath.Join(parent, "root")
				mkdirAll(t, root)
				link(t, outside, filepath.Join(root, ".claude"))
				return root
			},
		},
		{
			name:  "a relative target traversing out of the root",
			probe: ".claude",
			build: func(t *testing.T, parent string) string {
				outside := filepath.Join(parent, "outside")
				mkdirAll(t, outside)
				writeFile(t, filepath.Join(outside, "settings.json"), linkHookSettings)
				root := filepath.Join(parent, "root")
				mkdirAll(t, root)
				link(t, filepath.Join("..", "outside"), filepath.Join(root, ".claude"))
				return root
			},
		},
		{
			name:  "an in-root absolute target reached through an escaping ancestor",
			probe: ".claude",
			build: func(t *testing.T, parent string) string {
				outside := filepath.Join(parent, "outside")
				mkdirAll(t, filepath.Join(outside, "claude"))
				writeFile(t, filepath.Join(outside, "claude", "settings.json"), linkHookSettings)
				root := filepath.Join(parent, "root")
				mkdirAll(t, root)
				link(t, outside, filepath.Join(root, "vendor"))
				link(t, filepath.Join(root, "vendor", "claude"), filepath.Join(root, ".claude"))
				return root
			},
		},
		{
			name:  "a sibling whose name merely extends the root's",
			probe: ".claude",
			build: func(t *testing.T, parent string) string {
				root := filepath.Join(parent, "proj")
				mkdirAll(t, root)
				evil := filepath.Join(parent, "projevil", "claude")
				mkdirAll(t, evil)
				writeFile(t, filepath.Join(evil, "settings.json"), linkHookSettings)
				link(t, evil, filepath.Join(root, ".claude"))
				return root
			},
		},
		{
			name:  "an in-root absolute target carrying a traversal segment",
			probe: ".claude",
			build: func(t *testing.T, parent string) string {
				outside := filepath.Join(parent, "outside")
				mkdirAll(t, outside)
				writeFile(t, filepath.Join(outside, "settings.json"), linkHookSettings)
				root := filepath.Join(parent, "root")
				mkdirAll(t, root)
				link(t, root+string(filepath.Separator)+".."+string(filepath.Separator)+"outside", filepath.Join(root, ".claude"))
				return root
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := tt.build(t, canonicalDir(t))
			lfs, raw := openRoots(t, root)

			_, rawErr := fs.Stat(raw, tt.probe)
			if rawErr == nil {
				t.Fatalf("the raw containment root resolves %q, so this fixture exercises nothing", tt.probe)
			}
			if _, err := fs.Stat(lfs, tt.probe); err == nil {
				t.Fatalf("Stat(%q) succeeded, want the containment root's refusal preserved", tt.probe)
			}
			if _, err := fs.ReadFile(lfs, tt.probe+"/settings.json"); err == nil {
				t.Fatalf("ReadFile(%q) succeeded, want out-of-tree content never surfaced", tt.probe+"/settings.json")
			}
		})
	}
}

func TestLinkFS_RebaseNeverFoldsCase(t *testing.T) {
	root := canonicalDir(t)
	lfs, _ := openRoots(t, root)

	if rel, ok := lfs.rebase(filepath.Join(root, "config")); !ok || rel != "config" {
		t.Fatalf("rebase(<root>/config) = %q, %v, want %q and true", rel, ok, "config")
	}
	folded := filepath.Join(strings.ToUpper(root), "config")
	if rel, ok := lfs.rebase(folded); ok {
		t.Fatalf("rebase(%q) = %q, true, want it refused: the root prefix differs by case", folded, rel)
	}
}

// The escaping-ancestor case above would pass just as well if rebase had
// declined it, leaving lexical containment as the only guard.
func TestLinkFS_EscapingAncestorRebasesAndTheRootStillRefuses(t *testing.T) {
	parent := canonicalDir(t)
	outside := filepath.Join(parent, "outside")
	mkdirAll(t, filepath.Join(outside, "claude"))
	writeFile(t, filepath.Join(outside, "claude", "settings.json"), linkHookSettings)
	root := filepath.Join(parent, "root")
	mkdirAll(t, root)
	link(t, outside, filepath.Join(root, "vendor"))
	link(t, filepath.Join(root, "vendor", "claude"), filepath.Join(root, ".claude"))

	lfs, raw := openRoots(t, root)

	resolved, err := lfs.resolve(".claude", linkRewriteBudget)
	if err != nil || resolved != "vendor/claude" {
		t.Fatalf("resolve(.claude) = %q, %v, want %q and no error: the link text is spelled inside the root", resolved, err, "vendor/claude")
	}
	if _, err := fs.Stat(raw, resolved); err == nil {
		t.Fatalf("the containment root resolves %q, so nothing but the rewrite would be refusing the escape", resolved)
	}
}

func TestLinkFS_AbsentPathBehindAResolvedLinkReportsNotExist(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, "config"))
	link(t, filepath.Join(root, "config"), filepath.Join(root, ".claude"))

	lfs, _ := openRoots(t, root)

	_, err := fs.ReadFile(lfs, ".claude/absent.json")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile(.claude/absent.json) error = %v, want fs.ErrNotExist", err)
	}
}

func TestLinkFS_DanglingInRootAbsoluteLinkReportsNotExist(t *testing.T) {
	root := canonicalDir(t)
	link(t, filepath.Join(root, "gone"), filepath.Join(root, ".claude"))

	lfs, _ := openRoots(t, root)

	_, err := fs.Stat(lfs, ".claude")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(.claude) error = %v, want fs.ErrNotExist", err)
	}
}

// A cycle spelled absolutely cannot be broken by the containment root's own
// hop limit, because the root refuses the first hop outright.
func TestLinkFS_AbsoluteCycleExhaustsTheRewriteBudget(t *testing.T) {
	root := canonicalDir(t)
	link(t, filepath.Join(root, "y"), filepath.Join(root, "x"))
	link(t, filepath.Join(root, "x"), filepath.Join(root, "y"))

	lfs, _ := openRoots(t, root)

	_, err := fs.Stat(lfs, "x")
	if !errors.Is(err, errRewriteBudget) {
		t.Fatalf("Stat(x) error = %v, want errRewriteBudget", err)
	}
}

func TestLinkFS_AbsoluteCycleUnderAScanTerminatesAndWarns(t *testing.T) {
	root := canonicalDir(t)
	writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"fs":{"command":"npx"}}}`)
	link(t, filepath.Join(root, "y"), filepath.Join(root, "x"))
	link(t, filepath.Join(root, "x"), filepath.Join(root, "y"))

	lfs, _ := openRoots(t, root)

	var warnings []error
	sc := agentaudit.New(agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }))
	rep, err := sc.Scan(lfs)
	if err != nil {
		t.Fatalf("Scan error = %v, want the cycle degraded rather than fatal", err)
	}
	if !rep.HasFindings() {
		t.Fatalf("Scan found no capability, want the .mcp.json beside the cycle still reported")
	}
	if len(warnings) == 0 {
		t.Fatal("Scan emitted no warning, want the cycle surfaced instead of silently dropped")
	}
}

func TestLinkFS_LstatAndReadLinkReportTheLeafsOwnType(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, "config"))
	writeFile(t, filepath.Join(root, "config", "settings.json"), linkHookSettings)
	link(t, "settings.json", filepath.Join(root, "config", "alias.json"))
	link(t, filepath.Join(root, "config"), filepath.Join(root, ".claude"))

	lfs, _ := openRoots(t, root)

	info, err := fs.Lstat(lfs, ".claude/alias.json")
	if err != nil {
		t.Fatalf("Lstat(.claude/alias.json) error = %v", err)
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat(.claude/alias.json).Mode() = %v, want the leaf's own symlink bit", info.Mode())
	}

	target, err := fs.ReadLink(lfs, ".claude/alias.json")
	if err != nil {
		t.Fatalf("ReadLink(.claude/alias.json) error = %v", err)
	}
	if target != "settings.json" {
		t.Fatalf("ReadLink(.claude/alias.json) = %q, want the leaf's own target", target)
	}

	if _, err := fs.Lstat(lfs, ".claude"); err != nil {
		t.Fatalf("Lstat(.claude) error = %v, want the link itself still describable", err)
	}
}

func TestLinkFS_NonCanonicalRootSpellingResolvesBothWays(t *testing.T) {
	parent := canonicalDir(t)
	real := filepath.Join(parent, "real")
	mkdirAll(t, filepath.Join(real, "canonical"))
	mkdirAll(t, filepath.Join(real, "aliased"))
	writeFile(t, filepath.Join(real, "canonical", "settings.json"), linkHookSettings)
	writeFile(t, filepath.Join(real, "aliased", "settings.json"), linkHookSettings)

	alias := filepath.Join(parent, "alias")
	link(t, "real", alias)
	link(t, filepath.Join(real, "canonical"), filepath.Join(real, "viaCanonical"))
	link(t, filepath.Join(alias, "aliased"), filepath.Join(real, "viaAlias"))

	lfs, raw := openRoots(t, alias)
	for _, name := range []string{"viaCanonical", "viaAlias"} {
		mustRefuseRaw(t, raw, name)
		if _, err := fs.ReadFile(lfs, name+"/settings.json"); err != nil {
			t.Fatalf("ReadFile(%s/settings.json) error = %v, want both root spellings rebased", name, err)
		}
	}
}

func TestLinkFS_TransparentWithoutAnAbsoluteSymlink(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, ".claude"))
	mkdirAll(t, filepath.Join(root, "config"))
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), linkHookSettings)
	writeFile(t, filepath.Join(root, "config", "other.json"), `{}`)
	link(t, filepath.Join("..", "config"), filepath.Join(root, ".claude", "rel"))
	link(t, filepath.Join("..", "..", "escape"), filepath.Join(root, ".claude", "out"))
	link(t, "missing", filepath.Join(root, ".claude", "dangling"))

	lfs, raw := openRoots(t, root)

	walk := func(fsys fs.FS) []string {
		var got []string
		_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			got = append(got, fmt.Sprintf("%s|%v|%v", p, d != nil && d.IsDir(), err))
			return nil
		})
		return got
	}
	if decorated, bare := walk(lfs), walk(raw); !reflect.DeepEqual(decorated, bare) {
		t.Fatalf("WalkDir through the decorator = %v, want it identical to the bare root's %v", decorated, bare)
	}

	probes := []string{".", ".claude", ".claude/settings.json", ".claude/rel", ".claude/rel/other.json", ".claude/out", ".claude/dangling", ".claude/absent", "config"}
	for _, name := range probes {
		_, decorated := fs.Stat(lfs, name)
		_, bare := fs.Stat(raw, name)
		if fmt.Sprint(decorated) != fmt.Sprint(bare) {
			t.Errorf("Stat(%q) through the decorator = %v, want the bare root's %v", name, decorated, bare)
		}
		_, decorated = fs.ReadFile(lfs, name)
		_, bare = fs.ReadFile(raw, name)
		if fmt.Sprint(decorated) != fmt.Sprint(bare) {
			t.Errorf("ReadFile(%q) through the decorator = %v, want the bare root's %v", name, decorated, bare)
		}
		_, decorated = fs.ReadDir(lfs, name)
		_, bare = fs.ReadDir(raw, name)
		if fmt.Sprint(decorated) != fmt.Sprint(bare) {
			t.Errorf("ReadDir(%q) through the decorator = %v, want the bare root's %v", name, decorated, bare)
		}
		_, decorated = fs.Lstat(lfs, name)
		_, bare = fs.Lstat(raw, name)
		if fmt.Sprint(decorated) != fmt.Sprint(bare) {
			t.Errorf("Lstat(%q) through the decorator = %v, want the bare root's %v", name, decorated, bare)
		}
		_, decorated = fs.ReadLink(lfs, name)
		_, bare = fs.ReadLink(raw, name)
		if fmt.Sprint(decorated) != fmt.Sprint(bare) {
			t.Errorf("ReadLink(%q) through the decorator = %v, want the bare root's %v", name, decorated, bare)
		}
	}
}

// A refused path must name the spelling its caller asked for, never the
// rewritten one, so stderr keeps reading in the user's own terms.
func TestLinkFS_RefusalNamesTheCallersOwnPath(t *testing.T) {
	parent := canonicalDir(t)
	outside := filepath.Join(parent, "outside")
	mkdirAll(t, filepath.Join(outside, "claude"))
	root := filepath.Join(parent, "root")
	mkdirAll(t, root)
	link(t, outside, filepath.Join(root, "vendor"))
	link(t, filepath.Join(root, "vendor", "claude"), filepath.Join(root, ".claude"))

	lfs, _ := openRoots(t, root)

	_, err := fs.Stat(lfs, ".claude")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("Stat(.claude) error = %v, want an *fs.PathError", err)
	}
	if pathErr.Path != ".claude" {
		t.Fatalf("Stat(.claude) error path = %q, want %q", pathErr.Path, ".claude")
	}
}

// Resolution sits under the global config mask, so runtime state beside the
// declared entries stays denied whether or not a link would reach it.
func TestLinkFS_UnderTheGlobalMaskRuntimeStateStaysDenied(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, "dotfiles", "claude", "debug"))
	writeFile(t, filepath.Join(root, "dotfiles", "claude", "settings.json"), linkHookSettings)
	writeFile(t, filepath.Join(root, "dotfiles", "claude", "debug", "log.txt"), "debug")
	writeFile(t, filepath.Join(root, "dotfiles", "claude", "history.jsonl"), `{"text":"npx evil"}`)
	link(t, filepath.Join(root, "dotfiles", "claude"), filepath.Join(root, ".claude"))

	lfs, _ := openRoots(t, root)
	allow := map[string]bool{}
	for _, entry := range claude.New().GlobalConfig().Entries {
		allow[entry] = true
	}
	masked := maskFS{parent: lfs, allow: allow}

	if _, err := fs.ReadFile(masked, ".claude/settings.json"); err != nil {
		t.Fatalf("ReadFile(.claude/settings.json) error = %v, want the declared entry readable through the link", err)
	}
	for _, denied := range []string{".claude/debug", ".claude/debug/log.txt", ".claude/history.jsonl"} {
		if _, err := fs.Stat(masked, denied); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want fs.ErrNotExist from the mask", denied, err)
		}
	}
}

// countingFS counts parent Lstat and ReadLink calls, which the Stat and
// ReadFile probes below reach only from resolve.
type countingFS struct {
	parent    fs.FS
	lstats    int
	readlinks int
}

func (c *countingFS) Open(name string) (fs.File, error) { return c.parent.Open(name) }

func (c *countingFS) Stat(name string) (fs.FileInfo, error) { return fs.Stat(c.parent, name) }

func (c *countingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(c.parent, name)
}

func (c *countingFS) ReadFile(name string) ([]byte, error) { return fs.ReadFile(c.parent, name) }

func (c *countingFS) Lstat(name string) (fs.FileInfo, error) {
	c.lstats++
	return fs.Lstat(c.parent, name)
}

func (c *countingFS) ReadLink(name string) (string, error) {
	c.readlinks++
	return fs.ReadLink(c.parent, name)
}

// A loop the root refuses on its own hop budget costs no resolution walk,
// while an absolute target still pays for one. Over a tree of such loops
// that skipped walk is the whole cost.
func TestLinkFS_ResolutionIsSkippedForALoopAndRunForAnAbsoluteTarget(t *testing.T) {
	root := canonicalDir(t)
	mkdirAll(t, filepath.Join(root, "a"))
	link(t, "..", filepath.Join(root, "a", "up"))
	mkdirAll(t, filepath.Join(root, "config"))
	writeFile(t, filepath.Join(root, "config", "settings.json"), linkHookSettings)
	link(t, filepath.Join(root, "config"), filepath.Join(root, ".claude"))

	open := func() (linkFS, *countingFS) {
		t.Helper()
		r, err := os.OpenRoot(root)
		if err != nil {
			t.Fatalf("OpenRoot(%s) error = %v", root, err)
		}
		t.Cleanup(func() { _ = r.Close() })
		counter := &countingFS{parent: r.FS()}
		return linkFS{parent: counter, roots: newLinkFS(r.FS(), root).roots}, counter
	}

	loop := "a/up/a/up/a/up/a/up/a/up/a/up/a/up/a/up/a/up/a/up/x.json"
	lfs, counter := open()
	if _, err := fs.Stat(lfs, loop); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("Stat(%q) error = %v, want os.Root's hop-budget refusal: this fixture must exercise the skip", loop, err)
	}
	if counter.lstats != 0 || counter.readlinks != 0 {
		t.Fatalf("resolution walked the loop with %d Lstat and %d ReadLink calls, want none attempted", counter.lstats, counter.readlinks)
	}

	lfs, counter = open()
	if _, err := fs.ReadFile(lfs, ".claude/settings.json"); err != nil {
		t.Fatalf("ReadFile(.claude/settings.json) error = %v", err)
	}
	if counter.lstats == 0 {
		t.Fatal("resolution ran no Lstat for an absolute in-root target, so the zero asserted above proves nothing")
	}
}
