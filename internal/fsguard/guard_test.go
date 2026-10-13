package fsguard

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
)

const configJSON = `{"mcpServers":{"x":{"command":"npx"}}}`

func regular(data string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(data)} }

func symlink(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink}
}

func fifo(data string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(data), Mode: fs.ModeNamedPipe}
}

// tree holds an entry of each type the rows below name. The irregular entries
// carry bytes that would parse, so admitting one shows up as content rather
// than as a silent classification slip.
func tree() fstest.MapFS {
	return fstest.MapFS{
		"config.json":         regular(configJSON),
		"link-to-config.json": symlink("config.json"),
		"pipe.json":           fifo(configJSON),
		"link-to-pipe.json":   symlink("pipe.json"),
		"dangling.json":       symlink("nothing-here.json"),
		"link-to-dir":         symlink("dir"),
		"device.json":         &fstest.MapFile{Mode: fs.ModeDevice, Data: []byte(configJSON)},
		"dir/inner.json":      regular(configJSON),
	}
}

// listingFS withholds fs.ReadLinkFS and fs.StatFS, which the guards branch on.
// The map is held in a field: embedding it would promote Lstat and Stat, and
// the fallback arms would never run.
type listingFS struct{ m fstest.MapFS }

func (f listingFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f listingFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

type blockingOpenFS struct{ m fstest.MapFS }

func (f blockingOpenFS) Open(string) (fs.File, error) { select {} }

func (f blockingOpenFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

// lstatFaultFS reports fs.ReadLinkFS so fs.Lstat reaches its Lstat, then fails
// that call with something other than absence — an unreadable directory, a
// revoked permission — which a guard must not launder into a missing file.
type lstatFaultFS struct{ m fstest.MapFS }

func (f lstatFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f lstatFaultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func (f lstatFaultFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func (f lstatFaultFS) Lstat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrPermission}
}

func wantRefusal(t *testing.T, err error, p string) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want %q refused", p)
	}
	if !errors.Is(err, adapter.ErrUnreadable) {
		t.Errorf("error = %v, want errors.Is(_, adapter.ErrUnreadable)", err)
	}
	if !strings.Contains(err.Error(), p) {
		t.Errorf("error = %q, want it to name %q", err, p)
	}
}

func TestCheckRegularAdmitsOnlyAnEntryThatIsItselfARegularFile(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		admit bool
	}{
		{name: "a regular file", path: "config.json", admit: true},
		{name: "a symlink whose target is regular", path: "link-to-config.json"},
		{name: "a directory", path: "dir"},
		{name: "a FIFO", path: "pipe.json"},
		{name: "a device", path: "device.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckRegular(tree(), tt.path)
			if tt.admit {
				if err != nil {
					t.Fatalf("CheckRegular(%q) = %v, want nil", tt.path, err)
				}
				return
			}
			wantRefusal(t, err, tt.path)
		})
	}
}

// A link is judged by what it resolves to, and a refusal stays a refusal
// rather than becoming absence.
func TestCheckResolvedRegularReadsThroughALinkToARegularTarget(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		admit bool
	}{
		{name: "a regular file", path: "config.json", admit: true},
		{name: "a symlink whose target is regular", path: "link-to-config.json", admit: true},
		{name: "a symlink whose target is a FIFO", path: "link-to-pipe.json"},
		{name: "a symlink naming nothing", path: "dangling.json"},
		{name: "a FIFO", path: "pipe.json"},
		{name: "a directory", path: "dir"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckResolvedRegular(tree(), tt.path)
			if tt.admit {
				if err != nil {
					t.Fatalf("CheckResolvedRegular(%q) = %v, want nil", tt.path, err)
				}
				return
			}
			wantRefusal(t, err, tt.path)
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("error = %v, want a refusal rather than absence", err)
			}
		})
	}
}

// The open that fallback makes follows the link, so resolution would be
// bought by reading the target — the one cost this guard refuses to pay.
func TestCheckResolvedRegularRefusesALinkOnItsOwnModeWithoutFsStatFS(t *testing.T) {
	fsys := listingFS{m: tree()}

	if _, ok := fs.FS(fsys).(fs.StatFS); ok {
		t.Fatal("listingFS carries fs.StatFS, so the fallback this pins never runs")
	}
	wantRefusal(t, CheckResolvedRegular(fsys, "link-to-config.json"), "link-to-config.json")
}

// The checker's call count is the assertion: a type the walk already settled
// must not reach it.
func TestCheckEntryTypeConsultsTheCheckerForALinkAlone(t *testing.T) {
	checkerErr := errors.New("the checker ran")

	tests := []struct {
		name        string
		entryType   fs.FileMode
		wantCalls   int
		wantChecker bool
		wantRefusal bool
	}{
		{name: "a regular entry", entryType: 0},
		{name: "a symlink", entryType: fs.ModeSymlink, wantCalls: 1, wantChecker: true},
		{name: "a directory", entryType: fs.ModeDir, wantRefusal: true},
		{name: "a FIFO", entryType: fs.ModeNamedPipe, wantRefusal: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			err := CheckEntryType(tree(), "config.json", tt.entryType, func(fs.FS, string) error {
				calls++
				return checkerErr
			})

			if calls != tt.wantCalls {
				t.Fatalf("checker calls = %d, want %d", calls, tt.wantCalls)
			}
			switch {
			case tt.wantChecker:
				if !errors.Is(err, checkerErr) {
					t.Fatalf("error = %v, want the checker's own verdict", err)
				}
			case tt.wantRefusal:
				wantRefusal(t, err, "config.json")
			default:
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
			}
		})
	}
}

// The refusal reaches a config author as a Warning, so it names the path and
// the mode that settled it and nothing from the Go side of the boundary.
func TestIrregularRefusalNamesThePathAndTheModeWithoutAGoTypeName(t *testing.T) {
	err := IrregularRefusal("pipe.json", fs.ModeNamedPipe)

	const want = `refusing to read "pipe.json": not a regular file (p---------)`
	if got := err.Error(); got != want {
		t.Fatalf("IrregularRefusal() = %q, want %q", got, want)
	}
	if !errors.Is(err, adapter.ErrUnreadable) {
		t.Errorf("error = %v, want errors.Is(_, adapter.ErrUnreadable)", err)
	}
	for _, leak := range []string{"fs.FileMode", "fstest", "struct", "0x"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error = %q, must not leak a Go type name", err)
		}
	}
}

func TestReadResolvedRegularReturnsTheBytesBehindAnAdmittedPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "a regular file", path: "config.json"},
		{name: "a symlink whose target is regular", path: "link-to-config.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ReadResolvedRegular(tree(), tt.path)
			if err != nil {
				t.Fatalf("ReadResolvedRegular(%q) error = %v, want nil", tt.path, err)
			}
			if string(data) != configJSON {
				t.Fatalf("ReadResolvedRegular(%q) = %q, want %q", tt.path, data, configJSON)
			}
		})
	}
}

// An absent path names the read the guard stands in for rather than the
// classifier that ran first.
func TestReadResolvedRegularReportsAnAbsentPathAsAnOpenThatFoundNothing(t *testing.T) {
	tests := []struct {
		name string
		fsys fs.FS
	}{
		{name: "an FS reporting link modes", fsys: tree()},
		{name: "an FS answering from a listing", fsys: listingFS{m: tree()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadResolvedRegular(tt.fsys, "absent.json")
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("error = %v, want errors.Is(_, fs.ErrNotExist)", err)
			}
			var pathErr *fs.PathError
			if !errors.As(err, &pathErr) {
				t.Fatalf("error = %v, want an *fs.PathError", err)
			}
			if pathErr.Op != "open" || pathErr.Path != "absent.json" {
				t.Fatalf("error = %+v, want the open of %q the guard stands in for", pathErr, "absent.json")
			}
		})
	}
}

// A regression here stalls the scan rather than returning a wrong value, so
// the deadline is the assertion.
func TestReadResolvedRegularRefusesAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{"pipe.json": fifo(configJSON)}}

	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := ReadResolvedRegular(fsys, "pipe.json")
		done <- result{data, err}
	}()

	select {
	case got := <-done:
		if len(got.data) != 0 {
			t.Fatalf("data = %q, want none: the entry is refused, never read", got.data)
		}
		wantRefusal(t, got.err, "pipe.json")
	case <-time.After(10 * time.Second):
		t.Fatal("ReadResolvedRegular never returned; it opened the pipe instead of reading its type bits")
	}
}

// Every entry reports its own type bits rather than its target's.
func TestLinkModeReportsAnEntrysOwnTypeOnEitherFSShape(t *testing.T) {
	entries := []struct {
		name string
		path string
		want fs.FileMode
	}{
		{name: "a regular file", path: "config.json", want: 0},
		{name: "a symlink whose target is regular", path: "link-to-config.json", want: fs.ModeSymlink},
		{name: "a FIFO", path: "pipe.json", want: fs.ModeNamedPipe},
		{name: "a directory", path: "dir", want: fs.ModeDir},
		{name: "an entry beneath a directory", path: "dir/inner.json", want: 0},
	}

	for _, shape := range guardShapes() {
		t.Run(shape.name, func(t *testing.T) {
			for _, e := range entries {
				t.Run(e.name, func(t *testing.T) {
					mode, err := LinkMode(shape.fsys, e.path)
					if err != nil {
						t.Fatalf("LinkMode(%q) error = %v, want nil", e.path, err)
					}
					if mode != e.want {
						t.Fatalf("LinkMode(%q) = %s, want %s", e.path, mode, e.want)
					}
				})
			}

			t.Run("an absent entry", func(t *testing.T) {
				if _, err := LinkMode(shape.fsys, "absent.json"); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("LinkMode() error = %v, want errors.Is(_, fs.ErrNotExist)", err)
				}
			})
		})
	}
}

// Absence is the one classifier failure a caller may route to silence. A
// permission fault reported as absence would drop the source from the scan and
// report the tree as clean.
func TestLinkModeSurfacesAClassifierFaultThatIsNotAbsence(t *testing.T) {
	fsys := lstatFaultFS{m: tree()}

	if _, ok := fs.FS(fsys).(fs.ReadLinkFS); !ok {
		t.Fatal("lstatFaultFS is not an fs.ReadLinkFS, so fs.Lstat would fall back and the fault would never be injected")
	}

	_, err := LinkMode(fsys, "config.json")
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("LinkMode() error = %v, want errors.Is(_, fs.ErrPermission)", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LinkMode() error = %v, want the fault carried through rather than reported as absence", err)
	}

	if _, err := ReadResolvedRegular(fsys, "config.json"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ReadResolvedRegular() error = %v, want the same fault reaching the caller", err)
	}
}

// A real directory is admitted and every other entry at that path is refused,
// so a walk cannot be redirected by a link planted where a component root
// belongs. The fs.FS root is admitted as the scan boundary, and only the
// listing shape shows that arm doing anything: an fs.ReadLinkFS answers "."
// as a directory by itself, while the fallback hunts for "." among its
// parent's entries and finds nothing.
func TestCheckRealDirAdmitsOnlyAnEntryThatIsItselfADirectory(t *testing.T) {
	entries := []struct {
		name  string
		path  string
		admit bool
	}{
		{name: "a real directory", path: "dir", admit: true},
		{name: "the fs.FS root", path: ".", admit: true},
		{name: "a symlink whose target is a directory", path: "link-to-dir"},
		{name: "a regular file", path: "config.json"},
		{name: "a FIFO", path: "pipe.json"},
		{name: "a device", path: "device.json"},
	}

	for _, shape := range guardShapes() {
		t.Run(shape.name, func(t *testing.T) {
			for _, e := range entries {
				t.Run(e.name, func(t *testing.T) {
					err := CheckRealDir(shape.fsys, e.path)
					if e.admit {
						if err != nil {
							t.Fatalf("CheckRealDir(%q) = %v, want nil", e.path, err)
						}
						return
					}
					wantRefusal(t, err, e.path)
				})
			}
		})
	}
}

// Absence reports itself as absence, so a caller can tell a component root
// that is not there from one it must refuse to walk.
func TestCheckRealDirReportsAnAbsentPathAsAbsent(t *testing.T) {
	for _, shape := range guardShapes() {
		t.Run(shape.name, func(t *testing.T) {
			err := CheckRealDir(shape.fsys, "no-such-dir")

			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("CheckRealDir() = %v, want errors.Is(_, fs.ErrNotExist)", err)
			}
			if errors.Is(err, adapter.ErrUnreadable) {
				t.Fatalf("CheckRealDir() = %v, want absence rather than a refusal", err)
			}
		})
	}
}

// guardShapes pairs the FS shapes LinkMode branches on, so a row that an
// fs.ReadLinkFS answers on its own still reaches the listing fallback.
func guardShapes() []struct {
	name string
	fsys fs.FS
} {
	return []struct {
		name string
		fsys fs.FS
	}{
		{name: "through fs.ReadLinkFS", fsys: tree()},
		{name: "through the parent listing", fsys: listingFS{m: tree()}},
	}
}

// Only a directory target, or one that cannot be resolved for a reason other
// than absence, may hide entries behind a link.
func TestLinkMayHideEntriesOnlyOverADirectoryOrAnUnresolvableTarget(t *testing.T) {
	fsys := fstest.MapFS{
		"over-nothing": symlink("nowhere"),
		"over-a-file":  symlink("file"),
		"over-a-dir":   symlink("dir"),
		"over-a-pipe":  symlink("pipe"),
		"file":         regular("x"),
		"dir/inner":    regular("x"),
		"pipe":         fifo(""),
	}
	for p, want := range map[string]bool{
		"over-nothing": false,
		"over-a-file":  false,
		"over-a-pipe":  false,
		"over-a-dir":   true,
	} {
		if got := LinkMayHideEntries(fsys, p); got != want {
			t.Errorf("LinkMayHideEntries(%q) = %v, want %v", p, got, want)
		}
	}
	if !LinkMayHideEntries(listingFS{m: fsys}, "over-a-file") {
		t.Errorf("LinkMayHideEntries() without fs.StatFS = false, want true")
	}
	if !LinkMayHideEntries(statFaultFS{m: fsys}, "over-a-file") {
		t.Errorf("LinkMayHideEntries() over a Stat fault = false, want true")
	}
}

func TestResolvedModeReportsTheTargetOrFailsWithoutStatFS(t *testing.T) {
	fsys := fstest.MapFS{
		"link": symlink("file"),
		"file": &fstest.MapFile{Data: []byte("x"), Mode: 0o755},
	}
	mode, err := ResolvedMode(fsys, "link")
	if err != nil || !mode.IsRegular() || mode.Perm() != 0o755 {
		t.Errorf("ResolvedMode() = (%v, %v), want the target's regular 0755 mode", mode, err)
	}
	if _, err := ResolvedMode(listingFS{m: fsys}, "link"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("ResolvedMode() without fs.StatFS error = %v, want errors.ErrUnsupported", err)
	}
}

type statFaultFS struct{ m fstest.MapFS }

func (f statFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f statFaultFS) Stat(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "statat", Path: name, Err: errors.New("path escapes from parent")}
}
