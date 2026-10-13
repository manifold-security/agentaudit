package codex

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func skillFile() *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("---\nname: probe\ndescription: probe\n---\n")}
}

func script() *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("#!/bin/sh\n")}
}

func skillScript(p string) ir.BundledPayload {
	return ir.BundledPayload{
		Path:      p,
		Extension: ".sh",
		Origin:    "skill",
		Location:  ir.Location{File: p},
	}
}

// A skill below an intermediate directory is read like one directly beneath
// the root, and a scripts directory is walked to any depth. What a skill
// holds outside scripts/ is not code it bundles.
func TestSkillEntitiesReportEveryFileUnderASkillsScriptsDirectory(t *testing.T) {
	const direct = skillsRoot + "/deploy"
	const nested = skillsRoot + "/ops/rotate"

	fsys := fstest.MapFS{
		direct + "/SKILL.md":                 skillFile(),
		direct + "/scripts/deploy.sh":        {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		direct + "/scripts/Setup.PS1":        {Data: []byte("Write-Output 1\n")},
		direct + "/run.sh":                   {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		direct + "/references/guide.md":      {Data: []byte("# guide\n")},
		direct + "/agents/openai.yaml":       {Data: []byte("policy: {}\n")},
		nested + "/SKILL.md":                 skillFile(),
		nested + "/scripts/lib/key.py":       {Data: []byte("payload\n")},
		nested + "/assets/template.txt":      {Data: []byte("template\n")},
		skillsRoot + "/ops/scripts/stray.sh": script(),
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.BundledPayload{
			Path:      direct + "/scripts/Setup.PS1",
			Extension: ".ps1",
			Origin:    "skill",
			Location:  ir.Location{File: direct + "/scripts/Setup.PS1"},
		},
		ir.BundledPayload{
			Path:       direct + "/scripts/deploy.sh",
			Extension:  ".sh",
			Executable: "true",
			Origin:     "skill",
			Location:   ir.Location{File: direct + "/scripts/deploy.sh"},
		},
		ir.BundledPayload{
			Path:      nested + "/scripts/lib/key.py",
			Extension: ".py",
			Origin:    "skill",
			Location:  ir.Location{File: nested + "/scripts/lib/key.py"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
}

// A directory with no SKILL.md is not a skill, so a scripts directory inside
// it holds no code Codex loads and is walked like any other directory, down to
// a skill below it.
func TestSkillEntitiesLeaveAScriptsDirectoryWithoutASkillFileAlone(t *testing.T) {
	fsys := fstest.MapFS{
		skillsRoot + "/draft/scripts/draft.sh":                 script(),
		skillsRoot + "/draft/scripts/nested/SKILL.md":          skillFile(),
		skillsRoot + "/draft/scripts/nested/scripts/nested.sh": script(),
		skillsRoot + "/draft/notes.md":                         {Data: []byte("# notes\n")},
		skillsRoot + "/ship/SKILL.md":                          skillFile(),
		skillsRoot + "/ship/scripts/ship.sh":                   script(),
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{
		skillScript(skillsRoot + "/draft/scripts/nested/scripts/nested.sh"),
		skillScript(skillsRoot + "/ship/scripts/ship.sh"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
}

// A link at SKILL.md still makes its directory a skill and costs no Warning,
// and the scripts that skill bundles are reported.
func TestSkillEntitiesAnchorASkillOnASymlinkedSkillFileWithoutReadingIt(t *testing.T) {
	const skill = skillsRoot + "/deploy/SKILL.md"

	fsys := openCountingFS{
		m: fstest.MapFS{
			skill:                                 {Mode: fs.ModeSymlink, Data: []byte("../../../shared/SKILL.md")},
			skillsRoot + "/deploy/scripts/run.sh": script(),
			"shared/SKILL.md":                     skillFile(),
		},
		opens: map[string]int{},
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{skillScript(skillsRoot + "/deploy/scripts/run.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	if n := fsys.opens[skill]; n != 0 {
		t.Fatalf("skillEntities() opened %q %d time(s), want 0", skill, n)
	}

	if _, err := fs.ReadFile(fsys, skill); err != nil {
		t.Fatalf("fs.ReadFile(%q) error = %v", skill, err)
	}
	if n := fsys.opens[skill]; n != 1 {
		t.Fatalf("a direct read counted %d open(s) of %q, want 1, so the zero above measured nothing", n, skill)
	}
}

type openCountingFS struct {
	m     fstest.MapFS
	opens map[string]int
}

func (f openCountingFS) Open(name string) (fs.File, error) {
	f.opens[name]++
	return f.m.Open(name)
}

func (f openCountingFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func (f openCountingFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f openCountingFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f openCountingFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

// A directory named SKILL.md declares no skill, so the scripts beside it are
// not code Codex loads.
func TestSkillEntitiesLeaveADirectoryNamedSkillFileUnanchored(t *testing.T) {
	fsys := fstest.MapFS{
		skillsRoot + "/draft/SKILL.md/notes.md": {Data: []byte("# notes\n")},
		skillsRoot + "/draft/scripts/draft.sh":  script(),
		skillsRoot + "/ship/SKILL.md":           skillFile(),
		skillsRoot + "/ship/scripts/ship.sh":    script(),
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
}

type caseFoldFS struct {
	m fstest.MapFS
}

func (f caseFoldFS) resolve(name string) string {
	resolved := "."
	for _, part := range strings.Split(name, "/") {
		entries, err := f.m.ReadDir(resolved)
		if err != nil {
			return name
		}
		match := ""
		for _, e := range entries {
			if strings.EqualFold(e.Name(), part) {
				match = e.Name()
				break
			}
		}
		if match == "" {
			return name
		}
		resolved = path.Join(resolved, match)
	}
	return resolved
}

func (f caseFoldFS) Open(name string) (fs.File, error) { return f.m.Open(f.resolve(name)) }

func (f caseFoldFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(f.resolve(name)) }

func (f caseFoldFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(f.resolve(name)) }

func (f caseFoldFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(f.resolve(name)) }

func (f caseFoldFS) ReadLink(name string) (string, error) { return f.m.ReadLink(f.resolve(name)) }

// On a case-insensitive filesystem a script under Scripts/ is reachable as
// scripts/, so the directory is a skill's scripts directory whatever its
// case. Every path keeps the spelling the listing gives it, and the link
// inside it warns once.
func TestSkillEntitiesMatchTheScriptsDirectoryByItsListedSpelling(t *testing.T) {
	const link = skillsRoot + "/a/Scripts/l.sh"

	fsys := caseFoldFS{m: fstest.MapFS{
		skillsRoot + "/a/SKILL.md":           skillFile(),
		skillsRoot + "/a/Scripts/real.sh":    script(),
		link:                                 {Mode: fs.ModeSymlink, Data: []byte("real.sh")},
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
	}}
	if _, err := fs.Stat(fsys, skillsRoot+"/a/scripts"); err != nil {
		t.Fatalf("fs.Stat(%q) error = %v, want the double to fold case", skillsRoot+"/a/scripts", err)
	}

	got, warnings := skillEntities(fsys)
	want := []ir.Entity{
		skillScript(skillsRoot + "/a/Scripts/real.sh"),
		skillScript(skillsRoot + "/ship/scripts/ship.sh"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, link)
}

// A case-sensitive filesystem can hold several spellings of scripts in one
// skill, including one that sorts ahead of SKILL.md. Each is read under its
// own spelling, and a link in one of them warns once.
func TestSkillEntitiesReadEverySpellingOfTheScriptsDirectory(t *testing.T) {
	const skill = skillsRoot + "/multi"
	const link = skill + "/Scripts/l.sh"

	fsys := fstest.MapFS{
		skill + "/SCRIPTS/early.sh": script(),
		skill + "/SKILL.md":         skillFile(),
		skill + "/Scripts/mixed.sh": script(),
		link:                        {Mode: fs.ModeSymlink, Data: []byte("mixed.sh")},
		skill + "/scripts/lower.sh": script(),
	}

	got, warnings := skillEntities(fsys)
	want := []ir.Entity{
		skillScript(skill + "/SCRIPTS/early.sh"),
		skillScript(skill + "/Scripts/mixed.sh"),
		skillScript(skill + "/scripts/lower.sh"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, link)
}

// Any spelling of the skill file makes its directory a skill, a link at that
// name included, and costs no Warning of its own.
func TestSkillEntitiesAnchorASkillOnAnySpellingOfTheSkillFile(t *testing.T) {
	fsys := fstest.MapFS{
		skillsRoot + "/mixed/Skill.md":         skillFile(),
		skillsRoot + "/mixed/scripts/mixed.sh": script(),
		skillsRoot + "/linked/skill.MD":        {Mode: fs.ModeSymlink, Data: []byte("../mixed/Skill.md")},
		skillsRoot + "/linked/scripts/l.sh":    script(),
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{
		skillScript(skillsRoot + "/linked/scripts/l.sh"),
		skillScript(skillsRoot + "/mixed/scripts/mixed.sh"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
}

// A scripts entry that is not a directory is refused alone: what the skill
// directory lists after it, a nested skill and a link, is still read.
func TestSkillEntitiesKeepWhatSortsAfterARefusedScriptsEntry(t *testing.T) {
	const skill = skillsRoot + "/ship"

	tests := []struct {
		name    string
		scripts *fstest.MapFile
	}{
		{"a regular file", &fstest.MapFile{Data: []byte("not a directory\n")}},
		{"a symlink", &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("../ship/sub/scripts")}},
		{"a FIFO", &fstest.MapFile{Mode: fs.ModeNamedPipe}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := blockingOpenFS{m: fstest.MapFS{
				skill + "/SKILL.md":           skillFile(),
				skill + "/scripts":            tt.scripts,
				skill + "/sub/SKILL.md":       skillFile(),
				skill + "/sub/scripts/sub.sh": script(),
				skill + "/zlink":              {Mode: fs.ModeSymlink, Data: []byte("sub")},
			}}

			type result struct {
				entities []ir.Entity
				warnings []adapter.Warning
			}
			done := make(chan result, 1)
			go func() {
				entities, warnings := skillEntities(fsys)
				done <- result{entities, warnings}
			}()
			var got []ir.Entity
			var warnings []adapter.Warning
			select {
			case r := <-done:
				got, warnings = r.entities, r.warnings
			case <-time.After(10 * time.Second):
				t.Fatal("skillEntities never returned; it opened an entry instead of reading its type bits")
			}

			want := []ir.Entity{skillScript(skill + "/sub/scripts/sub.sh")}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			var files []string
			for _, w := range warnings {
				if !errors.Is(w.Err, adapter.ErrUnreadable) {
					t.Errorf("warning %v is not an adapter.ErrUnreadable", w.Err)
				}
				files = append(files, w.File)
			}
			if wantFiles := []string{skill + "/scripts", skill + "/zlink"}; !reflect.DeepEqual(files, wantFiles) {
				t.Fatalf("warnings name %q, want %q", files, wantFiles)
			}
		})
	}
}

// Only the name scripts, in any case, is a skill's scripts directory: a
// directory that merely starts with it is not.
func TestSkillEntitiesLeaveANameThatOnlyStartsWithScriptsUnclaimed(t *testing.T) {
	fsys := fstest.MapFS{
		skillsRoot + "/ship/SKILL.md":           skillFile(),
		skillsRoot + "/ship/scripts-old/old.sh": script(),
		skillsRoot + "/ship/scriptsx/x.sh":      script(),
		skillsRoot + "/ship/scripts/ship.sh":    script(),
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
}

type readDirCountingFS struct {
	m     fstest.MapFS
	lists map[string]int
}

func (f readDirCountingFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f readDirCountingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	f.lists[name]++
	return f.m.ReadDir(name)
}

func (f readDirCountingFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f readDirCountingFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f readDirCountingFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

// Each directory of a skills tree is listed once, scripts directories
// included.
func TestSkillEntitiesListEachDirectoryOnce(t *testing.T) {
	fsys := readDirCountingFS{
		m: fstest.MapFS{
			skillsRoot + "/ops/rotate/SKILL.md":         skillFile(),
			skillsRoot + "/ops/rotate/scripts/lib/k.sh": script(),
			skillsRoot + "/ops/rotate/references/r.md":  {Data: []byte("# r\n")},
			skillsRoot + "/ship/SKILL.md":               skillFile(),
			skillsRoot + "/ship/scripts/ship.sh":        script(),
		},
		lists: map[string]int{},
	}

	if got, _ := skillEntities(fsys); len(got) != 2 {
		t.Fatalf("skillEntities() = %+v, want both scripts", got)
	}
	want := map[string]int{
		skillsRoot:                             1,
		skillsRoot + "/ops":                    1,
		skillsRoot + "/ops/rotate":             1,
		skillsRoot + "/ops/rotate/scripts":     1,
		skillsRoot + "/ops/rotate/scripts/lib": 1,
		skillsRoot + "/ops/rotate/references":  1,
		skillsRoot + "/ship":                   1,
		skillsRoot + "/ship/scripts":           1,
	}
	if !reflect.DeepEqual(fsys.lists, want) {
		t.Fatalf("listings = %v, want %v", fsys.lists, want)
	}
}

// A Warning names a refused skill-folder link, and the real skill beside it
// in the same directory still reaches the report.
func TestSkillEntitiesWarnAboutASymlinkedSkillFolderAndKeepItsSibling(t *testing.T) {
	const linked = skillsRoot + "/linked"

	fsys := fstest.MapFS{
		linked:                               {Mode: fs.ModeSymlink, Data: []byte("../../shared/linked")},
		"shared/linked/SKILL.md":             skillFile(),
		"shared/linked/scripts/exfil.sh":     script(),
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
	}

	got, warnings := skillEntities(fsys)
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, linked)
}

// A symlinked script is refused on its own type bits and named, and the
// regular script beside it in the same directory is still reported.
func TestSkillEntitiesWarnAboutASymlinkedScriptAndKeepItsSibling(t *testing.T) {
	const linked = skillsRoot + "/ship/scripts/linked.sh"

	fsys := fstest.MapFS{
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
		linked:                               {Mode: fs.ModeSymlink, Data: []byte("ship.sh")},
	}

	got, warnings := skillEntities(fsys)
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, linked)
}

// A symlinked scripts directory is refused before the walk it would redirect,
// and the skill beside it still reaches the report.
func TestSkillEntitiesWarnAboutASymlinkedScriptsDirectoryAndKeepTheSiblingSkill(t *testing.T) {
	const linked = skillsRoot + "/deploy/scripts"

	fsys := fstest.MapFS{
		skillsRoot + "/deploy/SKILL.md":      skillFile(),
		linked:                               {Mode: fs.ModeSymlink, Data: []byte("../../../offtree")},
		"offtree/exfil.sh":                   script(),
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
	}

	got, warnings := skillEntities(fsys)
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, linked)
}

func assertOneRefusal(t *testing.T, warnings []adapter.Warning, file string) {
	t.Helper()
	if len(warnings) != 1 || warnings[0].File != file {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, file)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
	}
}

// Neither a FIFO script nor a FIFO SKILL.md is opened: the script is refused
// on its type bits and named, the skill file only has to exist, and the
// regular script beside the pipe is still reported.
func TestSkillEntitiesRefuseAFIFOWithoutOpeningIt(t *testing.T) {
	const piped = skillsRoot + "/ship/scripts/piped.sh"

	fsys := blockingOpenFS{m: fstest.MapFS{
		skillsRoot + "/ship/SKILL.md":        {Mode: fs.ModeNamedPipe},
		skillsRoot + "/ship/scripts/ship.sh": script(),
		piped:                                {Mode: fs.ModeNamedPipe},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings := skillEntities(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
		if !reflect.DeepEqual(got.entities, want) {
			t.Fatalf("skillEntities() = %+v, want %+v", got.entities, want)
		}
		assertOneRefusal(t, got.warnings, piped)
	case <-time.After(10 * time.Second):
		t.Fatal("skillEntities never returned; it opened a pipe instead of reading its type bits")
	}
}

type readDirFaultFS struct {
	m   fstest.MapFS
	dir string
}

func (f readDirFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f readDirFaultFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f readDirFaultFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f readDirFaultFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func (f readDirFaultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.dir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrPermission}
	}
	return f.m.ReadDir(name)
}

// A directory that cannot be listed names itself in a Warning, whether it is
// a skill's scripts directory or one holding skills, and the skill beside it
// still reaches the report.
func TestSkillEntitiesWarnAboutAnUnlistableDirectoryAndKeepTheSiblingSkill(t *testing.T) {
	tests := []struct {
		name       string
		unlistable string
	}{
		{"a skill's scripts directory", skillsRoot + "/deploy/scripts"},
		{"a directory holding skills", skillsRoot + "/ops"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := readDirFaultFS{
				m: fstest.MapFS{
					skillsRoot + "/deploy/SKILL.md":              skillFile(),
					skillsRoot + "/deploy/scripts/deploy.sh":     script(),
					skillsRoot + "/ops/rotate/SKILL.md":          skillFile(),
					skillsRoot + "/ops/rotate/scripts/rotate.sh": script(),
					skillsRoot + "/ship/SKILL.md":                skillFile(),
					skillsRoot + "/ship/scripts/ship.sh":         script(),
				},
				dir: tt.unlistable,
			}

			got, warnings := skillEntities(fsys)
			var want []ir.Entity
			for _, p := range []string{
				skillsRoot + "/deploy/scripts/deploy.sh",
				skillsRoot + "/ops/rotate/scripts/rotate.sh",
				skillsRoot + "/ship/scripts/ship.sh",
			} {
				if !strings.HasPrefix(p, tt.unlistable+"/") {
					want = append(want, skillScript(p))
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			if len(warnings) != 1 || warnings[0].File != tt.unlistable {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.unlistable)
			}
			if !errors.Is(warnings[0].Err, fs.ErrPermission) {
				t.Fatalf("warning %v does not carry the listing fault", warnings[0].Err)
			}
		})
	}
}

// The skills root is refused on its own type bits, so a link planted there
// cannot redirect the walk.
func TestSkillEntitiesRefuseASkillsRootThatIsNotARealDirectory(t *testing.T) {
	tests := []struct {
		name  string
		files fstest.MapFS
	}{
		{
			name: "the skills root is a symlink",
			files: fstest.MapFS{
				skillsRoot:                      {Mode: fs.ModeSymlink, Data: []byte("../offtree")},
				"offtree/deploy/SKILL.md":       skillFile(),
				"offtree/deploy/scripts/run.sh": script(),
			},
		},
		{
			name:  "the skills root is a regular file",
			files: fstest.MapFS{skillsRoot: {Data: []byte("not a directory\n")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := skillEntities(tt.files)
			if len(got) != 0 {
				t.Fatalf("skillEntities() = %+v, want none", got)
			}
			assertOneRefusal(t, warnings, skillsRoot)
		})
	}
}

// Silence and refusal have to be different answers.
func TestSkillEntitiesStaySilentWithoutASkillsRoot(t *testing.T) {
	got, warnings := skillEntities(fstest.MapFS{
		".agents/notes.md": {Data: []byte("# notes\n")},
	})
	if len(got) != 0 || len(warnings) != 0 {
		t.Fatalf("skillEntities() = (%+v, %+v), want neither", got, warnings)
	}
}

// The skills root is reachable from Parse, and a skill tree alone is enough.
func TestParseSurfacesTheScriptsASkillBundles(t *testing.T) {
	entities, warnings, err := New().Parse(fstest.MapFS{
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
	})
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() = %+v, want %+v", entities, want)
	}
}

// A link the walk does not select counts only where it could hide something:
// a directory target, or one that fails to stat for a reason other than
// absence. One over nothing, a file or a pipe shows as much as that entry
// would, while a link at or inside a skill's scripts entry keeps its
// refusal, and the skill beside it is reported either way.
func TestSkillEntitiesRefuseALinkOnlyWhereItCouldHideSomething(t *testing.T) {
	tests := []struct {
		link     string
		target   string
		fault    bool
		wantWarn bool
	}{
		{link: skillsRoot + "/y", target: "file", fault: true, wantWarn: true},
		{link: skillsRoot + "/z/" + skillFileName, target: "dir", wantWarn: true},
		{link: skillsRoot + "/z/Skill.md", target: "dir", wantWarn: true},
		{link: skillsRoot + "/z/" + skillFileName, target: "nowhere"},
		{link: skillsRoot + "/y", target: "nowhere"},
		{link: skillsRoot + "/x/notes.txt", target: "nowhere"},
		{link: skillsRoot + "/x/notes.txt", target: "file"},
		{link: skillsRoot + "/x/notes.txt", target: "pipe"},
		{link: skillsRoot + "/y", target: "dir", wantWarn: true},
		{link: skillsRoot + "/x/scripts", target: "nowhere", wantWarn: true},
		{link: skillsRoot + "/x/scripts/lnk.sh", target: "nowhere", wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.link+"->"+tt.target, func(t *testing.T) {
			m := fstest.MapFS{
				skillsRoot + "/x/SKILL.md":           skillFile(),
				skillsRoot + "/ship/SKILL.md":        skillFile(),
				skillsRoot + "/ship/scripts/ship.sh": script(),
				"shared/file":                        {Data: []byte("notes\n")},
				"shared/pipe":                        {Mode: fs.ModeNamedPipe},
				"shared/dir/SKILL.md":                skillFile(),
				"shared/dir/scripts/inner.sh":        script(),
			}
			m[tt.link] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(strings.Repeat("../", strings.Count(tt.link, "/")) + "shared/" + tt.target)}
			var fsys fs.FS = m
			if tt.fault {
				fsys = statFaultFS{m: m, fault: tt.link}
			}

			got, warnings := skillEntities(fsys)
			want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			if tt.wantWarn {
				assertOneRefusal(t, warnings, tt.link)
			} else if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
		})
	}
}

// A SKILL.md reached only through a link whose target fails to stat is not
// an anchor, so scripts beside it stay unread the way a link to a directory
// does.
func TestSkillEntitiesDoNotAnchorOnASkillFileLinkThatFailsToStat(t *testing.T) {
	const link = skillsRoot + "/z/" + skillFileName

	m := fstest.MapFS{
		link:                                 {Mode: fs.ModeSymlink, Data: []byte("../../../shared/file")},
		skillsRoot + "/z/scripts/a.sh":       script(),
		"shared/file":                        {Data: []byte("notes\n")},
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
	}

	got, warnings := skillEntities(statFaultFS{m: m, fault: link})
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, link)
}

type statFaultFS struct {
	m     fstest.MapFS
	fault string
}

func (f statFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f statFaultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func (f statFaultFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f statFaultFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func (f statFaultFS) Stat(name string) (fs.FileInfo, error) {
	if name == f.fault {
		return nil, &fs.PathError{Op: "statat", Path: name, Err: errors.New("path escapes from parent")}
	}
	return f.m.Stat(name)
}

// A skill-file link to a directory is refused and makes nothing a skill, the
// way a real directory of that name does, so scripts beside it are not
// reported as the skill's.
func TestSkillEntitiesDoNotAnchorOnASkillFileLinkToADirectory(t *testing.T) {
	const link = skillsRoot + "/z/" + skillFileName

	got, warnings := skillEntities(fstest.MapFS{
		link:                                 {Mode: fs.ModeSymlink, Data: []byte("../../../shared/d")},
		skillsRoot + "/z/scripts/a.sh":       script(),
		"shared/d/SKILL.md":                  skillFile(),
		"shared/d/scripts/b.sh":              script(),
		skillsRoot + "/ship/SKILL.md":        skillFile(),
		skillsRoot + "/ship/scripts/ship.sh": script(),
	})
	want := []ir.Entity{skillScript(skillsRoot + "/ship/scripts/ship.sh")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skillEntities() = %+v, want %+v", got, want)
	}
	assertOneRefusal(t, warnings, link)
}
