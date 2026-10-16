package agentaudit_test

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

const uploadFolder = "myrepo"

// A project nested under one folder, as an archive of that folder lays it
// out, hides its root-anchored config from a scan; stripping the root
// UploadRoot names gives back the scan of the same files laid out flat.
func TestUploadRootStripsTheFolderAnArchiveNestsAProjectUnder(t *testing.T) {
	projects := uploadProjects(t)
	hidden := 0

	for _, project := range projects {
		t.Run(project, func(t *testing.T) {
			flat := loadUploadFixture(t, path.Join("testdata", project))
			nested := fstest.MapFS{}
			var names []string
			for name, file := range flat {
				nested[uploadFolder+"/"+name] = file
				names = append(names, uploadFolder+"/"+name)
			}
			slices.Sort(names)

			root, err := agentaudit.UploadRoot(names)
			if err != nil {
				t.Fatalf("UploadRoot() error = %v, want nil", err)
			}
			if root != uploadFolder {
				t.Errorf("UploadRoot() = %q, want %q", root, uploadFolder)
			}

			want := uploadScanLines(t, flat)
			if got := uploadScanLines(t, stripUploadRoot(nested, root)); !slices.Equal(got, want) {
				t.Fatalf("scan after stripping %q:\n%s\nwant the flat scan:\n%s", root, strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if len(uploadScanLines(t, nested)) < len(want) {
				hidden++
			}
		})
	}

	if hidden == 0 {
		t.Fatalf("no project among %d lost a finding while nested, so the comparison above proved nothing about the stripped root", len(projects))
	}
}

func TestUploadRootLeavesASetWithRootLevelConfigUnstripped(t *testing.T) {
	paths := []string{".claude/settings.json", ".mcp.json", "src/main.go"}

	root, err := agentaudit.UploadRoot(paths)
	if err != nil || root != "" {
		t.Fatalf("UploadRoot(%q) = %q, %v, want \"\", nil", paths, root, err)
	}
}

// A set no root can be chosen for is refused with an error naming the path
// or folder in question.
func TestUploadRootRefusesASetItCannotRoot(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		named string
	}{
		{name: "an ambiguous root", paths: []string{".claude/settings.json", ".claude/.mcp.json"}, named: ".claude"},
		{name: "a marker folder", paths: []string{".claude-plugin/plugin.json", ".claude-plugin/README.md"}, named: ".claude-plugin"},
		{name: "config only below the root", paths: []string{"projects/myrepo/.claude/settings.json"}, named: "projects/myrepo"},
		{name: "an invalid name", paths: []string{"../x"}, named: "../x"},
		{name: "a directory-style name", paths: []string{"myrepo/a/", "myrepo/.claude/settings.json"}, named: "myrepo/a/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, err := agentaudit.UploadRoot(tc.paths)
			if err == nil || !strings.Contains(err.Error(), strconv.Quote(tc.named)) {
				t.Fatalf("UploadRoot(%q) = %q, %v, want an error naming %q", tc.paths, root, err, tc.named)
			}
		})
	}
}

func uploadProjects(t *testing.T) []string {
	t.Helper()

	testdata := os.DirFS("testdata")
	matches, err := fs.Glob(testdata, "*/*")
	if err != nil {
		t.Fatalf("fs.Glob(testdata) error = %v", err)
	}
	var projects []string
	for _, match := range matches {
		info, err := fs.Stat(testdata, match)
		if err != nil {
			t.Fatalf("fs.Stat(%q) error = %v", match, err)
		}
		if info.IsDir() {
			projects = append(projects, match)
		}
	}
	if len(projects) == 0 {
		t.Fatalf("no fixture project found under testdata; an empty enumeration must not pass silently")
	}
	return projects
}

func loadUploadFixture(t *testing.T, dir string) fstest.MapFS {
	t.Helper()

	tree := os.DirFS(dir)
	files := fstest.MapFS{}
	err := fs.WalkDir(tree, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(tree, name)
		if err != nil {
			return err
		}
		files[name] = &fstest.MapFile{Data: data}
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir(%q) error = %v", dir, err)
	}
	if len(files) == 0 {
		t.Fatalf("%q holds no file", dir)
	}
	return files
}

func stripUploadRoot(nested fstest.MapFS, root string) fstest.MapFS {
	if root == "" {
		return nested
	}
	stripped := fstest.MapFS{}
	for name, file := range nested {
		stripped[strings.TrimPrefix(name, root+"/")] = file
	}
	return stripped
}

func uploadScanLines(t *testing.T, fsys fs.FS) []string {
	t.Helper()

	report, err := agentaudit.New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	lines := []string{fmt.Sprintf("unreadable=%d unparsed=%d agents=%v", report.UnreadableSources(), report.UnparsedSources(), report.ScannedAgents())}
	for _, f := range report.Findings() {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%v\t%s\t%v\t%+v\t%T%+v",
			f.RuleID, f.Agent, f.Categories, f.Message, f.References,
			f.Capability.Provenance, f.Capability.Entity, f.Capability.Entity))
	}
	return lines
}
