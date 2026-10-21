package cursor

import (
	"errors"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// The walk a plugin's skills root gets applies to the project's own root
// too, scripts included.
func TestProjectSkillsSurfaceBelowAnIntermediateDirectoryWithTheirScripts(t *testing.T) {
	const direct = projectSkillsDir + "/deploy"
	const nested = projectSkillsDir + "/ops/rotate"

	fsys := fstest.MapFS{
		direct + "/SKILL.md":           named("deploy"),
		direct + "/scripts/deploy.sh":  {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		nested + "/SKILL.md":           named("rotate"),
		nested + "/scripts/lib/key.py": {Data: []byte("payload\n")},
	}

	got, warnings := skillEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "deploy",
			Location: ir.Location{File: direct + "/SKILL.md", Key: "name"},
		},
		ir.BundledPayload{
			Path:       direct + "/scripts/deploy.sh",
			Extension:  ".sh",
			Executable: "true",
			Origin:     "skill",
			Location:   ir.Location{File: direct + "/scripts/deploy.sh"},
		},
		ir.Skill{
			Name:     "rotate",
			Location: ir.Location{File: nested + "/SKILL.md", Key: "name"},
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

// The project's skills root is reachable from Parse. A surface the adapter
// declares and Parse never reads is one the scan prints a clean report over.
func TestParseSurfacesAProjectSkillAndTheScriptItBundles(t *testing.T) {
	const skillDir = projectSkillsDir + "/deploy"

	entities, warnings, err := New().Parse(fstest.MapFS{
		skillDir + "/SKILL.md":          named("deploy"),
		skillDir + "/scripts/deploy.sh": {Data: []byte("#!/bin/sh\n")},
	})
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "deploy",
			Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"},
		},
		ir.BundledPayload{
			Path:      skillDir + "/scripts/deploy.sh",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: skillDir + "/scripts/deploy.sh"},
		},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() = %+v, want %+v", entities, want)
	}
}

// The project's own skills root is refused on its own type bits too, so a
// link planted there cannot redirect the walk, for the reason the elsewhere
// closure in pluginmarkdown_test.go gives about a plugin's root.
func TestProjectSkillsRootRefusesWhatIsNotARealDirectory(t *testing.T) {
	tests := []struct {
		name  string
		files fstest.MapFS
	}{
		{
			name: "the skills root is a symlink",
			files: fstest.MapFS{
				projectSkillsDir:                {Mode: fs.ModeSymlink, Data: []byte("../offtree")},
				"offtree/deploy/SKILL.md":       named("offtree"),
				"offtree/deploy/scripts/run.sh": {Data: []byte("#!/bin/sh\n")},
			},
		},
		{
			name:  "the skills root is a regular file",
			files: fstest.MapFS{projectSkillsDir: {Data: []byte("not a directory\n")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := skillEntities(tt.files)
			if len(got) != 0 {
				t.Fatalf("skillEntities() = %+v, want none", got)
			}
			if len(warnings) != 1 || warnings[0].File != projectSkillsDir {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, projectSkillsDir)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
			}
		})
	}
}

// A project declaring no skills root costs no Warning, which is the
// companion the refusal above needs.
func TestProjectSkillsRootStaysSilentWhenAbsent(t *testing.T) {
	got, warnings := skillEntities(fstest.MapFS{
		mcpFileName: {Data: []byte(`{"mcpServers":{}}`)},
	})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	if len(got) != 0 {
		t.Fatalf("skillEntities() = %+v, want none", got)
	}
}

// A link where a skill folder could sit is named rather than followed or
// skipped, and the real skill beside it keeps its script in the report.
func TestProjectSkillsNameALinkedEntryAndKeepTheSkillBesideIt(t *testing.T) {
	const real = projectSkillsDir + "/real"

	tests := []struct {
		name  string
		link  string
		extra fstest.MapFS
	}{
		{name: "a skill folder", link: projectSkillsDir + "/linked"},
		{name: "a folder named scripts outside any skill", link: projectSkillsDir + "/scripts"},
		{name: "a folder inside a skill but outside its scripts", link: projectSkillsDir + "/real/nested"},
		{
			name:  "a folder named scripts beside a SKILL.md directory",
			link:  projectSkillsDir + "/odd/scripts",
			extra: fstest.MapFS{projectSkillsDir + "/odd/SKILL.md/notes.txt": {Data: []byte("x\n")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				tt.link:                  {Mode: fs.ModeSymlink, Data: []byte(strings.Repeat("../", strings.Count(tt.link, "/")) + "shared/sk")},
				"shared/sk/SKILL.md":     named("shared"),
				"shared/sk/scripts/x.sh": {Data: []byte("#!/bin/sh\n")},
				real + "/SKILL.md":       named("real"),
				real + "/scripts/r.sh":   {Data: []byte("#!/bin/sh\n")},
			}
			maps.Copy(fsys, tt.extra)

			got, warnings := skillEntities(fsys)

			want := []ir.Entity{
				ir.Skill{
					Name:     "real",
					Location: ir.Location{File: real + "/SKILL.md", Key: "name"},
				},
				ir.BundledPayload{
					Path:      real + "/scripts/r.sh",
					Extension: ".sh",
					Origin:    "skill",
					Location:  ir.Location{File: real + "/scripts/r.sh"},
				},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			if len(warnings) != 1 || warnings[0].File != tt.link {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.link)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
			}
		})
	}
}

// A skill folder link over nothing costs this walk no warning.
func TestProjectSkillsLeaveALinkOverNothingToDiscovery(t *testing.T) {
	const real = projectSkillsDir + "/real"

	got, warnings := skillEntities(fstest.MapFS{
		projectSkillsDir + "/linked": {Mode: fs.ModeSymlink, Data: []byte("nowhere")},
		real + "/SKILL.md":           named("real"),
	})
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none for a link over nothing", warnings)
	}
	want := []ir.Entity{ir.Skill{Name: "real", Location: ir.Location{File: real + "/SKILL.md", Key: "name"}}}
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

// A skill's scripts directory is matched whatever its case, and every path
// keeps the spelling its listing gives. On a case-insensitive filesystem a
// link inside Scripts/ is then named once, under that spelling.
func TestSkillScriptsAreMatchedByTheirListedSpelling(t *testing.T) {
	const skill = projectSkillsDir + "/cs"
	const link = skill + "/Scripts/lnk"

	files := fstest.MapFS{
		skill + "/SKILL.md":      named("cs"),
		skill + "/Scripts/ok.sh": {Data: []byte("#!/bin/sh\n")},
		link:                     {Mode: fs.ModeSymlink, Data: []byte("../../../../shared")},
		"shared/inner.sh":        {Data: []byte("#!/bin/sh\n")},
	}
	want := []ir.Entity{
		ir.Skill{Name: "cs", Location: ir.Location{File: skill + "/SKILL.md", Key: "name"}},
		ir.BundledPayload{
			Path:      skill + "/Scripts/ok.sh",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: skill + "/Scripts/ok.sh"},
		},
	}

	for name, fsys := range map[string]fs.FS{
		"case-insensitive": caseFoldFS{m: files},
		"case-sensitive":   files,
	} {
		t.Run(name, func(t *testing.T) {
			got, warnings := skillEntities(fsys)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			if len(warnings) != 1 || warnings[0].File != link {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
			}
		})
	}
}

// A single-skill plugin's scripts directory keeps its listed spelling too.
func TestRootSkillScriptsAreMatchedByTheirListedSpelling(t *testing.T) {
	const script = shipToolRoot + "/Scripts/run.sh"

	got, warnings, err := pluginComponentEntities(fstest.MapFS{
		shipToolRoot + "/SKILL.md": named("ship"),
		script:                     {Data: []byte("#!/bin/sh\n")},
	}, defaultPluginLayout(shipToolRoot))
	if err != nil {
		t.Fatalf("pluginComponentEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{
		ir.Skill{Name: "ship", Location: ir.Location{File: shipToolRoot + "/SKILL.md", Key: "name"}},
		ir.BundledPayload{Path: script, Extension: ".sh", Origin: "skill", Location: ir.Location{File: script}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginComponentEntities() = %+v, want %+v", got, want)
	}
}

// A plugin's skills root is walked the way the project's is, so a folder
// link there is named too.
func TestPluginSkillsNameALinkedSkillFolder(t *testing.T) {
	const link = shipToolRoot + "/skills/linked"

	got, warnings, err := pluginComponentEntities(fstest.MapFS{
		link:                                {Mode: fs.ModeSymlink, Data: []byte("../../../shared/sk")},
		"shared/sk/SKILL.md":                named("shared"),
		shipToolRoot + "/skills/r/SKILL.md": named("r"),
	}, defaultPluginLayout(shipToolRoot))
	if err != nil {
		t.Fatalf("pluginComponentEntities() error = %v, want nil", err)
	}
	want := []ir.Entity{ir.Skill{Name: "r", Location: ir.Location{File: shipToolRoot + "/skills/r/SKILL.md", Key: "name"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginComponentEntities() = %+v, want %+v", got, want)
	}
	if len(warnings) != 1 || warnings[0].File != link {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
	}
}

// A link over a file or a pipe under a name the walk never reads hides
// nothing a regular file there would show, so it stays as silent as one.
func TestProjectSkillsLeaveALinkUnderAnIgnoredNameSilent(t *testing.T) {
	const skill = projectSkillsDir + "/s"

	for _, target := range []string{"file", "pipe"} {
		t.Run(target, func(t *testing.T) {
			got, warnings := skillEntities(fstest.MapFS{
				skill + "/SKILL.md":  named("s"),
				skill + "/README.md": {Mode: fs.ModeSymlink, Data: []byte("../../../shared/" + target)},
				"shared/file":        {Data: []byte("# notes\n")},
				"shared/pipe":        {Mode: fs.ModeNamedPipe},
			})
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			want := []ir.Entity{ir.Skill{Name: "s", Location: ir.Location{File: skill + "/SKILL.md", Key: "name"}}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
		})
	}
}

// A skill file is matched whatever its case, and every path keeps the
// spelling its listing gives, so a link in the skill's scripts directory
// is named once.
func TestSkillFilesAreMatchedByTheirListedSpelling(t *testing.T) {
	const skill = projectSkillsDir + "/cs"
	const link = skill + "/Scripts/lnk"

	files := fstest.MapFS{
		skill + "/Skill.md":      named("cs"),
		skill + "/Scripts/ok.sh": {Data: []byte("#!/bin/sh\n")},
		link:                     {Mode: fs.ModeSymlink, Data: []byte("../../../../shared")},
		"shared/inner.sh":        {Data: []byte("#!/bin/sh\n")},
	}
	want := []ir.Entity{
		ir.Skill{Name: "cs", Location: ir.Location{File: skill + "/Skill.md", Key: "name"}},
		ir.BundledPayload{
			Path:      skill + "/Scripts/ok.sh",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: skill + "/Scripts/ok.sh"},
		},
	}

	for name, fsys := range map[string]fs.FS{
		"case-insensitive": caseFoldFS{m: files},
		"case-sensitive":   files,
	} {
		t.Run(name, func(t *testing.T) {
			got, warnings := skillEntities(fsys)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			if len(warnings) != 1 || warnings[0].File != link {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
			}
		})
	}
}

// A single-skill plugin's skill file keeps its listed spelling too.
func TestRootSkillFilesAreMatchedByTheirListedSpelling(t *testing.T) {
	const file = shipToolRoot + "/Skill.md"
	files := fstest.MapFS{file: named("ship")}
	want := []ir.Entity{ir.Skill{Name: "ship", Location: ir.Location{File: file, Key: "name"}}}

	for name, fsys := range map[string]fs.FS{
		"case-insensitive": caseFoldFS{m: files},
		"case-sensitive":   files,
	} {
		t.Run(name, func(t *testing.T) {
			got, warnings, err := pluginComponentEntities(fsys, defaultPluginLayout(shipToolRoot))
			if err != nil {
				t.Fatalf("pluginComponentEntities() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("pluginComponentEntities() = %+v, want %+v", got, want)
			}
		})
	}
}

type laterReadDirFaultFS struct {
	m     fstest.MapFS
	dir   string
	after int
	err   error
	calls *int
}

func (f laterReadDirFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f laterReadDirFaultFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f laterReadDirFaultFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f laterReadDirFaultFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func (f laterReadDirFaultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.dir {
		*f.calls++
		if *f.calls > f.after {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: f.err}
		}
	}
	return f.m.ReadDir(name)
}

// A skill directory that stops listing once its skill file is found names
// itself in a warning, unless it is simply gone, and the skill still counts.
func TestSkillScriptsListingFaultWarnsUnlessTheDirectoryIsGone(t *testing.T) {
	const skill = projectSkillsDir + "/cs"

	for _, tt := range []struct {
		err      error
		wantWarn bool
	}{
		{err: fs.ErrPermission, wantWarn: true},
		{err: fs.ErrNotExist},
	} {
		t.Run(tt.err.Error(), func(t *testing.T) {
			calls := 0
			got, warnings := skillEntities(laterReadDirFaultFS{
				m: fstest.MapFS{
					skill + "/SKILL.md":      named("cs"),
					skill + "/scripts/ok.sh": {Data: []byte("#!/bin/sh\n")},
				},
				dir: skill, after: 1, err: tt.err, calls: &calls,
			})
			if calls < 2 {
				t.Fatalf("the skill directory was listed %d times, want the scripts lookup to list it again", calls)
			}
			want := []ir.Entity{ir.Skill{Name: "cs", Location: ir.Location{File: skill + "/SKILL.md", Key: "name"}}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("skillEntities() = %+v, want %+v", got, want)
			}
			switch {
			case !tt.wantWarn && len(warnings) != 0:
				t.Fatalf("warnings = %+v, want none", warnings)
			case tt.wantWarn && (len(warnings) != 1 || warnings[0].File != skill || !errors.Is(warnings[0].Err, tt.err)):
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, skill)
			}
		})
	}
}

// A single-skill plugin root that cannot be listed names itself in a
// warning, so a skill file nothing listed is not a silent absence.
func TestRootSkillListingFaultWarns(t *testing.T) {
	calls := 0
	got, warnings, err := pluginComponentEntities(laterReadDirFaultFS{
		m:   fstest.MapFS{shipToolRoot + "/SKILL.md": named("ship")},
		dir: shipToolRoot, err: fs.ErrPermission, calls: &calls,
	}, defaultPluginLayout(shipToolRoot))
	if err != nil {
		t.Fatalf("pluginComponentEntities() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("pluginComponentEntities() = %+v, want none", got)
	}
	if len(warnings) != 1 || warnings[0].File != shipToolRoot || !errors.Is(warnings[0].Err, fs.ErrPermission) {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, shipToolRoot)
	}
}
