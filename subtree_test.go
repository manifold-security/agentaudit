package agentaudit

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// openOnlyFS has no Sub, matching os.Root.FS()'s own result.
type openOnlyFS struct{ fs.FS }

func methodSignature(m reflect.Method) string {
	t := m.Type
	ins := make([]string, 0, t.NumIn()-1)
	for i := 1; i < t.NumIn(); i++ {
		ins = append(ins, t.In(i).String())
	}
	outs := make([]string, 0, t.NumOut())
	for i := 0; i < t.NumOut(); i++ {
		outs = append(outs, t.Out(i).String())
	}
	return fmt.Sprintf("(%s) (%s)", strings.Join(ins, ", "), strings.Join(outs, ", "))
}

func TestSubtreeFSMethodSetMatchesStdlibSubResult(t *testing.T) {
	parent := openOnlyFS{fstest.MapFS{"a": &fstest.MapFile{}}}
	want, err := fs.Sub(parent, "d")
	if err != nil {
		t.Fatalf("fs.Sub() error = %v", err)
	}

	wantType := reflect.TypeOf(want)
	gotType := reflect.TypeOf(subtreeFS{})

	if wantType.NumMethod() == 0 {
		t.Fatalf("fs.Sub() result %s exposes no methods; the comparison below is vacuous", wantType)
	}

	for i := 0; i < wantType.NumMethod(); i++ {
		wm := wantType.Method(i)
		gm, ok := gotType.MethodByName(wm.Name)
		if !ok {
			t.Errorf("subtreeFS has no %s method; fs.Sub's result does", wm.Name)
			continue
		}
		if got, want := methodSignature(gm), methodSignature(wm); got != want {
			t.Errorf("subtreeFS.%s signature = %s, want %s", wm.Name, got, want)
		}
	}
}

type globParentFS struct{ m fstest.MapFS }

func (p globParentFS) Open(name string) (fs.File, error)     { return p.m.Open(name) }
func (p globParentFS) Glob(pattern string) ([]string, error) { return p.m.Glob(pattern) }

func TestSubtreeFSGlobShortensPaths(t *testing.T) {
	parent := globParentFS{m: fstest.MapFS{
		"nested/a.json": &fstest.MapFile{},
		"nested/b.json": &fstest.MapFile{},
		"other/c.json":  &fstest.MapFile{},
	}}
	s := subtreeFS{parent: parent, dir: "nested"}

	got, err := s.Glob("*.json")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	want := []string{"a.json", "b.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Glob() = %v, want %v", got, want)
	}
}

// wrappingFaultFS wraps its PathError with fmt.Errorf, the shape a caller of
// the public ScanRecursive seam could hand in.
type wrappingFaultFS struct{}

func (wrappingFaultFS) Open(name string) (fs.File, error) {
	return nil, fmt.Errorf("wrapped: %w", &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission})
}

// Only pathErr.Path is a claim this test can make; subtree.go's fixErr doc
// says why.
func TestSubtreeFSFixErrUnwrapsWrappedPathError(t *testing.T) {
	s := subtreeFS{parent: wrappingFaultFS{}, dir: "nested"}

	_, err := s.Open("blocked")
	if err == nil {
		t.Fatalf("Open() error = nil, want a wrapped PathError")
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("Open() error = %v, want it to wrap *fs.PathError", err)
	}
	if pathErr.Path != "blocked" {
		t.Fatalf("pathErr.Path = %q, want %q", pathErr.Path, "blocked")
	}
}

var errOpenPoisoned = errors.New("open poisoned")

type statOnlyFS struct{ m fstest.MapFS }

func (p statOnlyFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: errOpenPoisoned}
}
func (p statOnlyFS) Stat(name string) (fs.FileInfo, error) { return p.m.Stat(name) }

// fs.Sub over a subtreeFS must not fall back to the generic wrapper.
func TestSubtreeFSSubKeepsStatFS(t *testing.T) {
	parent := statOnlyFS{m: fstest.MapFS{"container/nested/child/file.txt": &fstest.MapFile{}}}
	root := subtreeFS{parent: parent, dir: "container/nested"}

	sub, err := fs.Sub(root, "child")
	if err != nil {
		t.Fatalf("fs.Sub() error = %v", err)
	}

	statter, ok := sub.(fs.StatFS)
	if !ok {
		t.Fatalf("fs.Sub() result does not implement fs.StatFS; Stat would fall back to the poisoned Open")
	}
	if _, err := statter.Stat("file.txt"); err != nil {
		t.Fatalf("Stat() error = %v, want nil", err)
	}
}

// full's fs.ValidPath check is all that stops ".." joining into the parent.
func TestSubtreeFSReadFileRejectsPathEscapingTheSubtree(t *testing.T) {
	parent := fstest.MapFS{
		"secret.txt":                   &fstest.MapFile{Data: []byte("top secret")},
		"nested/.claude/settings.json": &fstest.MapFile{},
	}
	s := subtreeFS{parent: parent, dir: "nested"}

	data, err := s.ReadFile("../secret.txt")
	if err == nil {
		t.Fatalf("ReadFile(%q) = %q, nil, want an error", "../secret.txt", data)
	}
	if !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("ReadFile(%q) error = %v, want fs.ErrInvalid", "../secret.txt", err)
	}
}

// subtree's own ValidPath(dir) check is independent of full's per-call one.
func TestSubtreeRejectsInvalidDir(t *testing.T) {
	_, err := subtree(fstest.MapFS{}, "../escape")
	if err == nil {
		t.Fatalf("subtree(fsys, %q) error = nil, want fs.ErrInvalid", "../escape")
	}
	if !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("subtree(fsys, %q) error = %v, want fs.ErrInvalid", "../escape", err)
	}
}

type readDirRootFaultFS struct {
	m        fstest.MapFS
	failPath string
}

func (f readDirRootFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f readDirRootFaultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failPath {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrPermission}
	}
	return f.m.ReadDir(name)
}

// A fault at a nested project's own root is rewritten only by shorten's
// name==s.dir branch: the suffix branch needs a "/" past s.dir.
func TestSubtreeFSFixErrShortensRootFault(t *testing.T) {
	parent := readDirRootFaultFS{
		m:        fstest.MapFS{"nested/.claude/settings.json": &fstest.MapFile{}},
		failPath: "nested",
	}
	s := subtreeFS{parent: parent, dir: "nested"}

	_, err := s.ReadDir(".")
	if err == nil {
		t.Fatalf("ReadDir(%q) error = nil, want a permission fault", ".")
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("ReadDir(%q) error = %v, want it to wrap *fs.PathError", ".", err)
	}
	if pathErr.Path != "." {
		t.Fatalf("pathErr.Path = %q, want %q", pathErr.Path, ".")
	}
}

var errCustomSubCalled = errors.New("custom sub called")

type customSubFS struct{ fstest.MapFS }

func (customSubFS) Sub(dir string) (fs.FS, error) { return nil, errCustomSubCalled }

// Wrapping fsys for dir=="." would shadow the caller's own Sub behavior.
func TestSubtreeDotDirReturnsFsysItself(t *testing.T) {
	parent := customSubFS{MapFS: fstest.MapFS{"a": &fstest.MapFile{}}}

	got, err := subtree(parent, ".")
	if err != nil {
		t.Fatalf("subtree() error = %v", err)
	}
	sub, ok := got.(fs.SubFS)
	if !ok {
		t.Fatalf("subtree(fsys, %q) does not implement fs.SubFS; fsys's own Sub was lost", ".")
	}
	if _, err := sub.Sub("anything"); !errors.Is(err, errCustomSubCalled) {
		t.Fatalf("Sub() error = %v, want %v (subtree(fsys, %q) must return fsys unchanged)", err, errCustomSubCalled, ".")
	}
}

var errGlobPoisoned = errors.New("glob poisoned")

type poisonedGlobFS struct{ fstest.MapFS }

func (poisonedGlobFS) Glob(pattern string) ([]string, error) { return nil, errGlobPoisoned }

// The "." shortcut must not reach the parent's Glob, matching stdlib subFS.
func TestSubtreeFSGlobDotPatternShortCircuits(t *testing.T) {
	parent := poisonedGlobFS{MapFS: fstest.MapFS{"nested/a.json": &fstest.MapFile{}}}
	s := subtreeFS{parent: parent, dir: "nested"}

	got, err := s.Glob(".")
	if err != nil {
		t.Fatalf("Glob(%q) error = %v, want nil", ".", err)
	}
	want := []string{"."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Glob(%q) = %v, want %v", ".", got, want)
	}
}

func TestSubtreeFSGlobRejectsMalformedPatternWithoutDelegating(t *testing.T) {
	parent := poisonedGlobFS{MapFS: fstest.MapFS{}}
	s := subtreeFS{parent: parent, dir: "nested"}

	_, err := s.Glob("[")
	if err == nil {
		t.Fatalf("Glob(%q) error = nil, want path.ErrBadPattern", "[")
	}
	if errors.Is(err, errGlobPoisoned) {
		t.Fatalf("Glob(%q) reached the parent's own Glob instead of rejecting locally", "[")
	}
	if !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("Glob(%q) error = %v, want path.ErrBadPattern", "[", err)
	}
}

// Companion arm for TestSubtreeFSGlobDotPatternShortCircuits and
// TestSubtreeFSGlobRejectsMalformedPatternWithoutDelegating: without a
// pattern that DOES reach poisonedGlobFS.Glob, both pass whether the poison
// exists or not.
func TestSubtreeFSGlobDelegatesAWellFormedPattern(t *testing.T) {
	parent := poisonedGlobFS{MapFS: fstest.MapFS{"nested/a.json": &fstest.MapFile{}}}
	s := subtreeFS{parent: parent, dir: "nested"}

	if _, err := s.Glob("*.json"); !errors.Is(err, errGlobPoisoned) {
		t.Fatalf("Glob(%q) error = %v, want %v", "*.json", err, errGlobPoisoned)
	}
}

// Glob must build its full pattern exactly as fs.Sub's own subFS does
// (dir + "/" + pattern, never path.Clean'd). The oracle is fs.Sub(parent,
// dir)'s Glob, not the unwrapped parent's — divergence there is the point.
func TestSubtreeFSGlobMatchesStdlibSubForDivergentPatterns(t *testing.T) {
	parent := globParentFS{m: fstest.MapFS{
		"nested/a.json":     &fstest.MapFile{},
		"nested/b.json":     &fstest.MapFile{},
		"nested/sub/b.json": &fstest.MapFile{},
		"outside/x.json":    &fstest.MapFile{},
	}}

	want, err := fs.Sub(parent, "nested")
	if err != nil {
		t.Fatalf("fs.Sub() error = %v", err)
	}
	wantGlob, ok := want.(fs.GlobFS)
	if !ok {
		t.Fatalf("fs.Sub() result does not implement fs.GlobFS")
	}
	got := subtreeFS{parent: parent, dir: "nested"}

	for _, pattern := range []string{"..", "*/", "sub//b.json", "../outside/*.json"} {
		t.Run(pattern, func(t *testing.T) {
			gotList, gotErr := got.Glob(pattern)
			wantList, wantErr := wantGlob.Glob(pattern)
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("Glob(%q) error = %v, want error matching stdlib's %v", pattern, gotErr, wantErr)
			}
			if gotErr != nil && gotErr.Error() != wantErr.Error() {
				t.Fatalf("Glob(%q) error = %q, want %q", pattern, gotErr, wantErr)
			}
			if !reflect.DeepEqual(gotList, wantList) {
				t.Fatalf("Glob(%q) = %v, want %v (stdlib fs.Sub result)", pattern, gotList, wantList)
			}
		})
	}
}

type leakyGlobFS struct{}

func (leakyGlobFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (leakyGlobFS) Glob(pattern string) ([]string, error) {
	return []string{"outside/leak.json"}, nil
}

func TestSubtreeFSGlobRejectsResultEscapingTheSubtree(t *testing.T) {
	s := subtreeFS{parent: leakyGlobFS{}, dir: "nested"}

	got, err := s.Glob("*.json")
	if err == nil {
		t.Fatalf("Glob() = %v, nil, want an error", got)
	}
	if got != nil {
		t.Fatalf("Glob() = %v, want nil on a containment failure", got)
	}
}

type globErrFS struct{}

func (globErrFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (globErrFS) Glob(pattern string) ([]string, error) {
	return nil, &fs.PathError{Op: "glob", Path: "nested/blocked", Err: fs.ErrPermission}
}

func TestSubtreeFSGlobRewritesErrorPath(t *testing.T) {
	s := subtreeFS{parent: globErrFS{}, dir: "nested"}

	_, err := s.Glob("*.json")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("Glob() error = %v, want it to wrap *fs.PathError", err)
	}
	if pathErr.Path != "blocked" {
		t.Fatalf("pathErr.Path = %q, want %q", pathErr.Path, "blocked")
	}
}

// parentNamespaceFaultFS echoes back the name it was handed, so a forwarder
// that skips the rewrite shows up as a path still spelled in the container's
// namespace. Its Op names the forwarder that was actually reached, which is
// what separates Lstat from fs.Lstat's fallback to Stat.
type parentNamespaceFaultFS struct{}

func (parentNamespaceFaultFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}

func (parentNamespaceFaultFS) Stat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
}

func (parentNamespaceFaultFS) ReadFile(name string) ([]byte, error) {
	return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrPermission}
}

func (parentNamespaceFaultFS) Lstat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrPermission}
}

func (parentNamespaceFaultFS) ReadLink(name string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrPermission}
}

// A warning built from the container's spelling names a path outside the
// namespace the caller scanned, so a project's own block under -r would cite
// a file belonging to the container. Each forwarder rewrites on its own, so
// an entry per forwarder keeps one regression from hiding behind another's
// guard.
func TestSubtreeFSForwardersRewriteFaultPath(t *testing.T) {
	s := subtreeFS{parent: parentNamespaceFaultFS{}, dir: "nested"}

	for _, tc := range []struct {
		method string
		wantOp string
		call   func() error
	}{
		{"Stat", "stat", func() error { _, err := s.Stat("blocked"); return err }},
		{"ReadFile", "readfile", func() error { _, err := s.ReadFile("blocked"); return err }},
		{"Lstat", "lstat", func() error { _, err := s.Lstat("blocked"); return err }},
		{"ReadLink", "readlink", func() error { _, err := s.ReadLink("blocked"); return err }},
	} {
		t.Run(tc.method, func(t *testing.T) {
			err := tc.call()
			var pathErr *fs.PathError
			if !errors.As(err, &pathErr) {
				t.Fatalf("%s() error = %v, want it to wrap *fs.PathError", tc.method, err)
			}
			if pathErr.Op != tc.wantOp {
				t.Fatalf("%s() pathErr.Op = %q, want %q (a fallback reached another forwarder)", tc.method, pathErr.Op, tc.wantOp)
			}
			if pathErr.Path != "blocked" {
				t.Fatalf("%s() pathErr.Path = %q, want %q", tc.method, pathErr.Path, "blocked")
			}
		})
	}
}
