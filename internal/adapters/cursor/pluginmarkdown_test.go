package cursor

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const shipToolManifest = shipToolRoot + "/.cursor-plugin/plugin.json"

func named(name string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("---\nname: " + name + "\ndescription: ships\n---\n\nbody\n")}
}

// An intermediate directory beneath the skills root organises the plugin's
// tree without being a skill itself, so a SKILL.md below one declares a skill
// exactly as a direct child does.
func TestPluginSkillsSurfaceBelowAnIntermediateDirectory(t *testing.T) {
	fsys := fstest.MapFS{
		shipToolManifest: manifest(`{"name":"ship-tool"}`),
		shipToolRoot + "/skills/release/SKILL.md":              named("release"),
		shipToolRoot + "/skills/internal/tools/audit/SKILL.md": named("audit"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "audit",
			Location: ir.Location{File: shipToolRoot + "/skills/internal/tools/audit/SKILL.md", Key: "name"},
		},
		ir.Skill{
			Name:     "release",
			Location: ir.Location{File: shipToolRoot + "/skills/release/SKILL.md", Key: "name"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// A bundled script reaches the report carrying the extension and the execute
// bit the tree gave it, and the directory boundary is exact: a sibling just
// outside it declares nothing.
func TestPluginSkillScriptsSurfaceAsBundledPayloads(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"

	fsys := fstest.MapFS{
		shipToolManifest:                    manifest(`{"name":"ship-tool"}`),
		skillDir + "/SKILL.md":              named("release"),
		skillDir + "/scripts/publish.sh":    {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		skillDir + "/scripts/lib/helper.py": {Data: []byte("payload\n")},
		skillDir + "/reference.md":          {Data: []byte("notes\n")},
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{Name: "release", Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"}},
		ir.BundledPayload{
			Path:      skillDir + "/scripts/lib/helper.py",
			Extension: ".py",
			Origin:    "skill",
			Location:  ir.Location{File: skillDir + "/scripts/lib/helper.py"},
		},
		ir.BundledPayload{
			Path:       skillDir + "/scripts/publish.sh",
			Extension:  ".sh",
			Executable: "true",
			Origin:     "skill",
			Location:   ir.Location{File: skillDir + "/scripts/publish.sh"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// A skills root suppresses the plugin root's own SKILL.md, and the scripts
// beside it with it. Absent one, it is the presence of an entry at that path
// that gates those scripts: a refused entry gates them in just as a readable
// one does, and no entry at all leaves them unread.
func TestPluginRootSkillYieldsToASkillsRoot(t *testing.T) {
	const rootSkill = shipToolRoot + "/SKILL.md"
	const rootScript = shipToolRoot + "/scripts/deploy.sh"

	executableScript := func() *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0o755}
	}

	tests := []struct {
		name  string
		files fstest.MapFS
		want  []ir.Entity
		// wantRefusal names the path this row's tree refuses, empty when it
		// refuses nothing.
		wantRefusal string
	}{
		{
			name: "the plugin root carries the only SKILL.md",
			files: fstest.MapFS{
				rootSkill:  named("ship"),
				rootScript: executableScript(),
			},
			want: []ir.Entity{
				ir.Skill{
					Name:     "ship",
					Location: ir.Location{File: rootSkill, Key: "name"},
				},
				ir.BundledPayload{
					Path:       rootScript,
					Extension:  ".sh",
					Executable: "true",
					Origin:     "skill",
					Location:   ir.Location{File: rootScript},
				},
			},
		},
		{
			// TestPluginMarkdownRefusesASymlinkedComponent owns why the
			// target is a readable regular file; the delta here is that the
			// scripts beside the link outlive it.
			name: "the plugin root's SKILL.md is a symlink",
			files: fstest.MapFS{
				rootSkill:                 {Mode: fs.ModeSymlink, Data: []byte("real.md")},
				shipToolRoot + "/real.md": named("ship"),
				rootScript:                executableScript(),
			},
			want: []ir.Entity{ir.BundledPayload{
				Path:       rootScript,
				Extension:  ".sh",
				Executable: "true",
				Origin:     "skill",
				Location:   ir.Location{File: rootScript},
			}},
			wantRefusal: rootSkill,
		},
		{
			name: "a skills root sits beside it",
			files: fstest.MapFS{
				rootSkill:  {Data: []byte("---\nname: ship\n---\n")},
				rootScript: executableScript(),
				shipToolRoot + "/skills/release/SKILL.md": named("release"),
			},
			want: []ir.Entity{ir.Skill{
				Name:     "release",
				Location: ir.Location{File: shipToolRoot + "/skills/release/SKILL.md", Key: "name"},
			}},
		},
		{
			name: "the plugin root carries scripts and no SKILL.md",
			files: fstest.MapFS{
				rootScript: executableScript(),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{shipToolManifest: manifest(`{"name":"ship-tool"}`)}
			for p, f := range tt.files {
				fsys[p] = f
			}

			got, warnings := componentsFrom(t, fsys)
			if tt.wantRefusal == "" {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %+v, want none", warnings)
				}
			} else {
				if len(warnings) != 1 || warnings[0].File != tt.wantRefusal {
					t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.wantRefusal)
				}
				if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
					t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pluginEntities() components = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A plugin's agents directory declares one subagent for each markdown
// spelling the adapter accepts. want below is exact, so whatever else the
// directory holds declares nothing.
func TestPluginAgentsSurfaceFromEveryAcceptedMarkdownSpelling(t *testing.T) {
	const agentsDir = shipToolRoot + "/agents"

	fsys := fstest.MapFS{
		shipToolManifest:                  manifest(`{"name":"ship-tool"}`),
		agentsDir + "/shipper.md":         named("shipper"),
		agentsDir + "/auditor.mdc":        named("auditor"),
		agentsDir + "/reviewer.markdown":  named("reviewer"),
		agentsDir + "/notes.txt":          {Data: []byte("---\nname: notes\n---\n")},
		agentsDir + "/nested/deep.md":     named("deep"),
		agentsDir + "/bundle.md/part.txt": {Data: []byte("not an agent\n")},
	}

	for ext := range agentFileExtensions {
		covered := false
		for p := range fsys {
			if strings.HasPrefix(p, agentsDir+"/") && path.Ext(p) == ext {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("the table carries no %q file, so that spelling goes unexercised", ext)
		}
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Subagent{Name: "auditor", Location: ir.Location{File: agentsDir + "/auditor.mdc", Key: "name"}},
		ir.Subagent{Name: "reviewer", Location: ir.Location{File: agentsDir + "/reviewer.markdown", Key: "name"}},
		ir.Subagent{Name: "shipper", Location: ir.Location{File: agentsDir + "/shipper.md", Key: "name"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// Each shape of a missing name costs the file itself and nothing else: one
// warning, no entity, on a skill and on an agent alike.
func TestPluginMarkdownNamingNothingDegrades(t *testing.T) {
	const skillFile = shipToolRoot + "/skills/release/SKILL.md"
	const agentFile = shipToolRoot + "/agents/shipper.md"

	tests := []struct {
		name string
		file string
		body string
	}{
		{name: "a skill with no frontmatter at all", file: skillFile, body: "run it\n"},
		{name: "a skill whose frontmatter declares no name", file: skillFile, body: "---\ndescription: ships\n---\n"},
		{name: "a skill whose frontmatter declares an empty name", file: skillFile, body: "---\nname: \"\"\n---\n"},
		{name: "a skill whose fence never closes", file: skillFile, body: "---\nname: release\n"},
		{name: "a skill whose frontmatter is not YAML", file: skillFile, body: "---\nname: [unclosed\n---\n"},
		{name: "an agent whose frontmatter declares no name", file: agentFile, body: "---\nmodel: fast\n---\n"},
		{name: "an agent whose fence never closes", file: agentFile, body: "---\nname: shipper\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				shipToolManifest: manifest(`{"name":"ship-tool"}`),
				tt.file:          {Data: []byte(tt.body)},
			}

			got, warnings := componentsFrom(t, fsys)
			if len(got) != 0 {
				t.Fatalf("pluginEntities() components = %+v, want none", got)
			}
			if len(warnings) != 1 || warnings[0].File != tt.file {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.file)
			}
		})
	}
}

// A markdown file in the agents directory with no frontmatter fence is prose
// the plugin ships, so it declares no subagent and reports no fault.
func TestPluginAgentsStaySilentOnAMarkdownFileWithNoFence(t *testing.T) {
	fsys := fstest.MapFS{
		shipToolManifest:                    manifest(`{"name":"ship-tool"}`),
		shipToolRoot + "/agents/README.md":  {Data: []byte("# how these agents work\n")},
		shipToolRoot + "/agents/shipper.md": named("shipper"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{ir.Subagent{
		Name:     "shipper",
		Location: ir.Location{File: shipToolRoot + "/agents/shipper.md", Key: "name"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// A component file reached through a symlink is refused on the link's own
// type bits rather than read through to its target, so a plugin cannot point
// one at a file outside the tree it was found in. Each link here resolves to
// a readable regular file, which leaves the link itself as the only ground
// for the refusal.
func TestPluginMarkdownRefusesASymlinkedComponent(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"

	tests := []struct {
		name string
		link string
		file fstest.MapFS
	}{
		{
			name: "a symlinked SKILL.md",
			link: skillDir + "/SKILL.md",
			file: fstest.MapFS{skillDir + "/real.md": named("release")},
		},
		{
			name: "a symlinked agent file",
			link: shipToolRoot + "/agents/shipper.md",
			file: fstest.MapFS{shipToolRoot + "/agents/real.txt": named("shipper")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{shipToolManifest: manifest(`{"name":"ship-tool"}`)}
			var target string
			for p, f := range tt.file {
				fsys[p] = f
				target = p
			}
			fsys[tt.link] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(path.Base(target))}

			got, warnings := componentsFrom(t, fsys)
			for _, e := range got {
				if _, isSubagent := e.(ir.Subagent); isSubagent {
					t.Fatalf("pluginEntities() surfaced %+v from a refused symlink", e)
				}
				if _, isSkill := e.(ir.Skill); isSkill {
					t.Fatalf("pluginEntities() surfaced %+v from a refused symlink", e)
				}
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

// A bundled payload reached through a symlink is refused for the reason
// TestPluginMarkdownRefusesASymlinkedComponent gives, while the regular file
// the link resolves to surfaces from the same walk.
func TestPluginSkillScriptsRefuseASymlinkedPayload(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"
	const link = skillDir + "/scripts/publish.sh"
	const target = skillDir + "/scripts/real"

	fsys := fstest.MapFS{
		shipToolManifest:       manifest(`{"name":"ship-tool"}`),
		skillDir + "/SKILL.md": named("release"),
		target:                 {Data: []byte("payload\n")},
		link:                   {Mode: fs.ModeSymlink, Data: []byte("real")},
	}

	got, warnings := componentsFrom(t, fsys)
	paths := map[string]bool{}
	for _, e := range got {
		if p, isPayload := e.(ir.BundledPayload); isPayload {
			paths[p.Path] = true
		}
	}
	if paths[link] {
		t.Fatalf("pluginEntities() surfaced a payload at %q, which is a symlink", link)
	}
	if !paths[target] {
		t.Fatalf("pluginEntities() payload paths = %v, want the regular file at %q among them", paths, target)
	}
	if len(warnings) != 1 || warnings[0].File != link {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
	}
}

// A stray symlink inside a skills root whose target fails to stat for a
// reason other than absence is refused; a dangling one is silent.
func TestPluginSkillsRefuseAStraySymlinkOnAStatFault(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"
	const link = skillDir + "/notes.md"

	tests := []struct {
		name     string
		fault    bool
		wantWarn bool
	}{
		{name: "dangling target", wantWarn: false},
		{name: "target fails to stat", fault: true, wantWarn: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := fstest.MapFS{
				shipToolManifest:       manifest(`{"name":"ship-tool"}`),
				skillDir + "/SKILL.md": named("release"),
				link:                   {Mode: fs.ModeSymlink, Data: []byte("../../../../shared/readme")},
			}
			var fsys fs.FS = m
			if tt.fault {
				m["shared/readme"] = &fstest.MapFile{Data: []byte("notes\n")}
				fsys = statFaultFS{m: m, fault: link}
			}

			got, warnings := componentsFrom(t, fsys)
			want := []ir.Entity{ir.Skill{
				Name:     "release",
				Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"},
			}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
			}
			if !tt.wantWarn {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %+v, want none", warnings)
				}
				return
			}
			if len(warnings) != 1 || warnings[0].File != link {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
			}
		})
	}
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

// The guards classify an entry from its parent's listing, so the refusal
// lands on the read rather than on the type check ahead of it.
type openFaultFS struct {
	m    fstest.MapFS
	path string
}

func (f openFaultFS) Open(name string) (fs.File, error) {
	if name == f.path {
		return nil, fs.ErrPermission
	}
	return f.m.Open(name)
}

func (f openFaultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

// A component location this scanner cannot read names itself in a Warning
// rather than passing for an absent one, and where a component sits outside
// the fault it still surfaces.
//
// The subject is the component reader rather than pluginEntities: the walk
// that finds a manifest reports an unlistable directory under a plugin root
// too, and what each row is about is the component site that meets the fault
// second.
func TestPluginComponentFaultsNameTheirOwnPath(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"
	const rootScripts = shipToolRoot + "/scripts"

	script := func() *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("#!/bin/sh\n")}
	}
	releaseSkill := ir.Skill{Name: "release", Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"}}
	bootPayload := ir.BundledPayload{
		Path:      rootScripts + "/boot.sh",
		Extension: ".sh",
		Origin:    "skill",
		Location:  ir.Location{File: rootScripts + "/boot.sh"},
	}

	tests := []struct {
		name        string
		fsys        fs.FS
		wantWarning string
		want        []ir.Entity
	}{
		{
			name: "the agents directory cannot be listed",
			fsys: readDirFaultFS{
				m: fstest.MapFS{
					skillDir + "/SKILL.md":              named("release"),
					shipToolRoot + "/agents/shipper.md": named("shipper"),
				},
				dir: shipToolRoot + "/agents",
			},
			wantWarning: shipToolRoot + "/agents",
			want:        []ir.Entity{releaseSkill},
		},
		{
			name: "an agent file cannot be read",
			fsys: openFaultFS{
				m: fstest.MapFS{
					skillDir + "/SKILL.md":              named("release"),
					shipToolRoot + "/agents/shipper.md": named("shipper"),
				},
				path: shipToolRoot + "/agents/shipper.md",
			},
			wantWarning: shipToolRoot + "/agents/shipper.md",
			want:        []ir.Entity{releaseSkill},
		},
		{
			name: "a directory under the skills root cannot be listed",
			fsys: readDirFaultFS{
				m: fstest.MapFS{
					shipToolRoot + "/skills/other/SKILL.md": named("other"),
					skillDir + "/SKILL.md":                  named("release"),
				},
				dir: skillDir,
			},
			wantWarning: skillDir,
			want: []ir.Entity{ir.Skill{
				Name:     "other",
				Location: ir.Location{File: shipToolRoot + "/skills/other/SKILL.md", Key: "name"},
			}},
		},
		{
			name: "a directory under a skill's scripts cannot be listed",
			fsys: readDirFaultFS{
				m: fstest.MapFS{
					shipToolRoot + "/SKILL.md":  named("ship"),
					rootScripts + "/boot.sh":    script(),
					rootScripts + "/lib/dep.py": script(),
				},
				dir: rootScripts + "/lib",
			},
			wantWarning: rootScripts + "/lib",
			want: []ir.Entity{
				ir.Skill{Name: "ship", Location: ir.Location{File: shipToolRoot + "/SKILL.md", Key: "name"}},
				bootPayload,
			},
		},
		{
			name: "the plugin root's own SKILL.md cannot be read",
			fsys: openFaultFS{
				m: fstest.MapFS{
					shipToolRoot + "/SKILL.md": named("ship"),
					rootScripts + "/boot.sh":   script(),
				},
				path: shipToolRoot + "/SKILL.md",
			},
			wantWarning: shipToolRoot + "/SKILL.md",
			want:        []ir.Entity{bootPayload},
		},
		{
			name: "a skill's SKILL.md cannot be read",
			fsys: openFaultFS{
				m: fstest.MapFS{
					skillDir + "/SKILL.md":          named("release"),
					skillDir + "/scripts/deploy.sh": script(),
				},
				path: skillDir + "/SKILL.md",
			},
			wantWarning: skillDir + "/SKILL.md",
			want: []ir.Entity{ir.BundledPayload{
				Path:      skillDir + "/scripts/deploy.sh",
				Extension: ".sh",
				Origin:    "skill",
				Location:  ir.Location{File: skillDir + "/scripts/deploy.sh"},
			}},
		},
		{
			// The fault is in the listing rather than in the entry's own
			// type, so the directory check ahead of it passes and the walk
			// is what reports.
			name: "the skills root cannot be listed",
			fsys: readDirFaultFS{
				m: fstest.MapFS{
					shipToolRoot + "/SKILL.md": named("ship"),
					skillDir + "/SKILL.md":     named("release"),
				},
				dir: shipToolRoot + "/skills",
			},
			wantWarning: shipToolRoot + "/skills",
			want:        []ir.Entity{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings, err := pluginComponentEntities(tt.fsys, defaultPluginLayout(shipToolRoot))
			if err != nil {
				t.Fatalf("pluginComponentEntities() error = %v, want nil: a faulty source degrades", err)
			}

			if len(warnings) != 1 || warnings[0].File != tt.wantWarning {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.wantWarning)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pluginComponentEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Each component root goes through fsguard.CheckRealDir, so a refused one
// names itself and contributes nothing. The elsewhere tree below is what
// makes the refusal observable: unguarded, its entries reach the result under
// the plugin's own paths. A root that is simply absent stays silent, which is
// what keeps a refusal distinguishable from nothing being there.
func TestPluginComponentRootsRefuseWhatIsNotARealDirectory(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"
	const releaseScripts = skillDir + "/scripts"

	// elsewhere is the tree a link would redirect a walk into. Each entry is
	// shaped like the component it would be taken for, so a guard that let the
	// link through shows up as a forged Location rather than as nothing.
	elsewhere := func(fsys fstest.MapFS) fstest.MapFS {
		fsys["elsewhere/release/SKILL.md"] = named("offtree")
		fsys["elsewhere/offtree.md"] = named("offtree")
		fsys["elsewhere/run.sh"] = &fstest.MapFile{Data: []byte("#!/bin/sh\n")}
		return fsys
	}
	releaseSkill := ir.Skill{Name: "release", Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"}}

	tests := []struct {
		name        string
		files       fstest.MapFS
		wantWarning string
		want        []ir.Entity
	}{
		{
			name: "the skills root is a symlink",
			files: elsewhere(fstest.MapFS{
				shipToolRoot + "/skills": {Mode: fs.ModeSymlink, Data: []byte("../../elsewhere")},
			}),
			wantWarning: shipToolRoot + "/skills",
		},
		{
			name: "the agents root is a symlink",
			files: elsewhere(fstest.MapFS{
				skillDir + "/SKILL.md":   named("release"),
				shipToolRoot + "/agents": {Mode: fs.ModeSymlink, Data: []byte("../../elsewhere")},
			}),
			wantWarning: shipToolRoot + "/agents",
			want:        []ir.Entity{releaseSkill},
		},
		{
			name: "a skill's scripts root is a symlink",
			files: elsewhere(fstest.MapFS{
				skillDir + "/SKILL.md": named("release"),
				releaseScripts:         {Mode: fs.ModeSymlink, Data: []byte("../../../../elsewhere")},
			}),
			wantWarning: releaseScripts,
			want:        []ir.Entity{releaseSkill},
		},
		{
			// A regular file is the entry a directory check answers on
			// without any listing being attempted.
			name: "the skills root is a regular file",
			files: fstest.MapFS{
				shipToolRoot + "/skills":   {Data: []byte("not a directory\n")},
				shipToolRoot + "/SKILL.md": named("ship"),
			},
			wantWarning: shipToolRoot + "/skills",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings, err := pluginComponentEntities(tt.files, defaultPluginLayout(shipToolRoot))
			if err != nil {
				t.Fatalf("pluginComponentEntities() error = %v, want nil: a refused root degrades", err)
			}

			for _, e := range got {
				if file := ir.LocationOf(e).File; strings.HasPrefix(file, tt.wantWarning+"/") {
					t.Fatalf("entity %+v carries a Location under %q, a path the scan did not read", e, tt.wantWarning)
				}
			}
			if !reflect.DeepEqual(got, append([]ir.Entity{}, tt.want...)) {
				t.Fatalf("pluginComponentEntities() = %+v, want %+v", got, tt.want)
			}
			if len(warnings) != 1 || warnings[0].File != tt.wantWarning {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.wantWarning)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
			}
		})
	}
}

// A component root that is simply not there costs no Warning, which is the
// companion the refusals above need: silence and refusal have to be different
// answers, or a reader cannot tell an absent root from an unread one.
func TestPluginComponentRootsStaySilentWhenAbsent(t *testing.T) {
	fsys := fstest.MapFS{shipToolRoot + "/mcp.json": manifest(`{"mcpServers":{}}`)}

	got, warnings, err := pluginComponentEntities(fsys, defaultPluginLayout(shipToolRoot))
	if err != nil {
		t.Fatalf("pluginComponentEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	if len(got) != 0 {
		t.Fatalf("pluginComponentEntities() = %+v, want none", got)
	}
}

// A component spelled in upper case is read exactly as a lower-case one is.
// A case-insensitive filesystem hands an author that spelling by accident,
// and without the folding the agent file matches no accepted extension and
// the payload reports an extension no rule author would write.
func TestPluginComponentsFoldTheCaseOfAnExtension(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"

	fsys := fstest.MapFS{
		shipToolManifest:                    manifest(`{"name":"ship-tool"}`),
		skillDir + "/SKILL.md":              named("release"),
		skillDir + "/scripts/DEPLOY.SH":     {Data: []byte("#!/bin/sh\n")},
		shipToolRoot + "/agents/SHIPPER.MD": named("shipper"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "release",
			Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"},
		},
		ir.BundledPayload{
			Path:      skillDir + "/scripts/DEPLOY.SH",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: skillDir + "/scripts/DEPLOY.SH"},
		},
		ir.Subagent{
			Name:     "shipper",
			Location: ir.Location{File: shipToolRoot + "/agents/SHIPPER.MD", Key: "name"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// A component written with CRLF endings declares its name exactly as an LF
// one does. The fence is matched on both sides of the block, so an author on
// Windows ships neither a skill this scanner degrades nor an agent it passes
// over in silence.
func TestPluginMarkdownReadsACRLFFrontmatterBlock(t *testing.T) {
	crlf := func(name string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("---\r\nname: " + name + "\r\ndescription: ships\r\n---\r\n\r\nbody\r\n")}
	}

	fsys := fstest.MapFS{
		shipToolManifest: manifest(`{"name":"ship-tool"}`),
		shipToolRoot + "/skills/release/SKILL.md": crlf("release"),
		shipToolRoot + "/agents/shipper.md":       crlf("shipper"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "release",
			Location: ir.Location{File: shipToolRoot + "/skills/release/SKILL.md", Key: "name"},
		},
		ir.Subagent{
			Name:     "shipper",
			Location: ir.Location{File: shipToolRoot + "/agents/shipper.md", Key: "name"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// Every payload a skill bundles carries the skill origin, whether a plugin
// ships that skill or the project declares it under its own skills root.
func TestSkillBundledPayloadsCarryTheSkillOrigin(t *testing.T) {
	const pluginSkill = shipToolRoot + "/skills/release"
	const projectSkill = projectSkillsDir + "/deploy"

	fsys := fstest.MapFS{
		shipToolManifest:                 manifest(`{"name":"ship-tool"}`),
		pluginSkill + "/SKILL.md":        named("release"),
		pluginSkill + "/scripts/pub.sh":  {Data: []byte("#!/bin/sh\n")},
		projectSkill + "/SKILL.md":       named("deploy"),
		projectSkill + "/scripts/run.sh": {Data: []byte("#!/bin/sh\n")},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	got := map[string]string{}
	for _, e := range entities {
		if p, isPayload := e.(ir.BundledPayload); isPayload {
			got[p.Path] = p.Origin
		}
	}
	want := map[string]string{
		pluginSkill + "/scripts/pub.sh":  "skill",
		projectSkill + "/scripts/run.sh": "skill",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payload origins = %v, want %v", got, want)
	}
}
