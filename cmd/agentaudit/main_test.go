package main

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func withScan(t *testing.T, fn func(fsys fs.FS, warn func(error)) (finding.Report, error)) {
	t.Helper()
	original := scan
	scan = func(fsys fs.FS, warn func(error), _ ...agentaudit.Option) (finding.Report, error) {
		return fn(fsys, warn)
	}
	t.Cleanup(func() { scan = original })
}

func withScanRecursive(t *testing.T, fn func(fsys fs.FS, warn func(error)) ([]agentaudit.ProjectReport, error)) {
	t.Helper()
	original := scanRecursive
	scanRecursive = func(fsys fs.FS, warn func(error), _ ...agentaudit.Option) ([]agentaudit.ProjectReport, error) {
		return fn(fsys, warn)
	}
	t.Cleanup(func() { scanRecursive = original })
}

func withScanGlobal(t *testing.T, fn func(fsys fs.FS, warn func(error)) (finding.Report, error)) {
	t.Helper()
	original := scanGlobal
	scanGlobal = func(fsys fs.FS, warn func(error), _ ...agentaudit.Option) (finding.Report, error) {
		return fn(fsys, warn)
	}
	t.Cleanup(func() { scanGlobal = original })
}

func emptyReportScan(fs.FS, func(error)) (finding.Report, error) {
	return finding.NewReport(nil), nil
}

func degradedEmptyReportScan(fs.FS, func(error)) (finding.Report, error) {
	return finding.NewReport(nil).WithUnreadableSources(1), nil
}

func findingsReportScan(fs.FS, func(error)) (finding.Report, error) {
	f := finding.Finding{
		RuleID:     "test.rule",
		Categories: []finding.Category{"test"},
		Capability: finding.Capability{
			Entity:     ir.EnvVar{Name: "X", Value: "y"},
			Provenance: finding.Provenance{File: "settings.json", Key: "env.X"},
		},
	}
	return finding.NewReport([]finding.Finding{f}), nil
}

// The bad-path row fails at open time, before scan runs, so it exercises
// the real opening wiring.
func TestRun_ExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		scanFunc func(fs.FS, func(error)) (finding.Report, error)
		want     int
	}{
		{name: "clean report exits 0", args: nil, scanFunc: emptyReportScan, want: 0},
		{name: "findings present exits 1", args: nil, scanFunc: findingsReportScan, want: 1},
		{name: "nonexistent path exits 2", args: []string{"/does/not/exist/agentaudit-test-fixture"}, want: 2},
		{name: "malformed args (too many positional) exits 2", args: []string{"one", "two"}, want: 2},
		{name: "degraded scan with no findings exits 0", args: nil, scanFunc: degradedEmptyReportScan, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.scanFunc != nil {
				withScan(t, tt.scanFunc)
			}

			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Fatalf("run(%v) = %d, want %d\nstdout: %s\nstderr: %s", tt.args, got, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

// run() adds exactly one "agentaudit:" prefix, whatever the error carries.
func TestRun_BadPathErrorHasNoDoublePrefix(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"usage fault already carries the prefix", []string{""}},
		{"open failure carries no prefix at all", []string{"/does/not/exist/agentaudit-test-fixture"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != 2 {
				t.Fatalf("run(%v) = %d, want 2\nstderr: %s", tt.args, got, stderr.String())
			}
			if got := strings.Count(stderr.String(), "agentaudit:"); got != 1 {
				t.Fatalf("stderr = %q, want exactly one \"agentaudit:\" occurrence, got %d", stderr.String(), got)
			}
		})
	}
}

// Cobra usage and help text must never pollute a passing run.
func TestRun_SuccessPathsLeakNoUsageText(t *testing.T) {
	tests := []struct {
		name     string
		scanFunc func(fs.FS, func(error)) (finding.Report, error)
	}{
		{"clean report", emptyReportScan},
		{"findings present", findingsReportScan},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withScan(t, tt.scanFunc)

			var stdout, stderr bytes.Buffer
			run(nil, &stdout, &stderr)
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty on a success path", stderr.String())
			}
		})
	}
}

func TestRun_PathDefaultsToDot(t *testing.T) {
	withScan(t, emptyReportScan)

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0", got)
	}
	if !strings.Contains(stdout.String(), "agentaudit · .\n") {
		t.Fatalf("stdout = %q, want header to show default path \".\"", stdout.String())
	}
}

func TestRun_ExplicitPathIsHonored(t *testing.T) {
	withScan(t, emptyReportScan)

	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if got := run([]string{dir}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "agentaudit · "+dir+"\n") {
		t.Fatalf("stdout = %q, want header to show explicit path %q", stdout.String(), dir)
	}
}

func TestRun_RoutesWarnFuncToStderrWithPrefix(t *testing.T) {
	withScan(t, func(fsys fs.FS, warn func(error)) (finding.Report, error) {
		warn(errors.New("agentaudit: discover: some/path: boom"))
		return finding.NewReport(nil), nil
	})

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0", got)
	}
	if !strings.Contains(stderr.String(), "warning: agentaudit: discover: some/path: boom") {
		t.Fatalf("stderr = %q, want a \"warning: \" line naming the reported error", stderr.String())
	}
}

func TestRun_OutputJSON_ProducesValidJSONFindingsArray(t *testing.T) {
	withScan(t, findingsReportScan)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-o", "json"}, &stdout, &stderr)
	if got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	var docs []struct {
		Findings []struct{} `json:"findings"`
	}
	if err := stdjson.Unmarshal(stdout.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, stdout.String())
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1 (one target)\nstdout: %s", len(docs), stdout.String())
	}
	if len(docs[0].Findings) != 1 {
		t.Fatalf("docs[0].Findings has %d entries, want 1\nstdout: %s", len(docs[0].Findings), stdout.String())
	}
}

func TestRun_OutputInvalid_Exits2WithUsageError(t *testing.T) {
	for _, format := range []string{"md", "yaml", "xml"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run([]string{"-o", format}, &stdout, &stderr)
			if got != 2 {
				t.Fatalf("run([-o %s]) = %d, want 2\nstderr: %s", format, got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "not a valid -o value") {
				t.Fatalf("stderr = %q, want it to contain \"not a valid -o value\"", stderr.String())
			}
			if format == "md" && !strings.Contains(stderr.String(), "-O md") {
				t.Fatalf("stderr = %q, want it to contain \"-O md\"", stderr.String())
			}
		})
	}
}

func TestRun_ExplainFlag_AddsFollowOnLineToPrettyOutput(t *testing.T) {
	withScan(t, findingsReportScan)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-v"}, &stdout, &stderr)
	if got != 1 {
		t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\n    test.rule\n") {
		t.Fatalf("stdout = %q, want an indented \"test.rule\" follow-on line", stdout.String())
	}
}

func TestRun_ExplainFlag_AbsentByDefault(t *testing.T) {
	withScan(t, findingsReportScan)

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
	}
	if strings.Contains(stdout.String(), "test.rule") {
		t.Fatalf("stdout = %q, want no rule id rendered without -v", stdout.String())
	}
}

// JSON already carries these fields structurally, so -v has nothing to add.
func TestRun_ExplainFlag_IgnoredWithJSONOutput(t *testing.T) {
	withScan(t, findingsReportScan)

	var withoutV, withV, stderr bytes.Buffer
	if got := run([]string{"-o", "json"}, &withoutV, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
	}
	stderr.Reset()
	if got := run([]string{"-o", "json", "-v"}, &withV, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
	}
	if withoutV.String() != withV.String() {
		t.Fatalf("-o json output changed by -v\n--- without -v ---\n%s\n--- with -v ---\n%s", withoutV.String(), withV.String())
	}
}

// -v threads only into pretty.Meta, so -O's files must not depend on it.
func TestRun_ExplainFlag_NeverAffectsOutputFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	withScan(t, findingsReportScan)

	if got := run([]string{"-O", "all"}, &bytes.Buffer{}, &bytes.Buffer{}); got != 1 {
		t.Fatalf("run() = %d, want 1", got)
	}
	withoutV := make(map[string][]byte)
	for _, name := range []string{jsonReportFilename, mdReportFilename} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, err)
		}
		withoutV[name] = data
	}

	if got := run([]string{"-O", "all", "-v"}, &bytes.Buffer{}, &bytes.Buffer{}); got != 1 {
		t.Fatalf("run() = %d, want 1", got)
	}
	for _, name := range []string{jsonReportFilename, mdReportFilename} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, err)
		}
		if !bytes.Equal(withoutV[name], data) {
			t.Fatalf("%s changed by -v\n--- without -v ---\n%s\n--- with -v ---\n%s", name, withoutV[name], data)
		}
	}
}

func TestRun_OutputFilesNotSpecified_WritesNoFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	withScan(t, findingsReportScan)

	if got := run([]string{"-o", "json"}, &bytes.Buffer{}, &bytes.Buffer{}); got != 1 {
		t.Fatalf("run() = %d, want 1", got)
	}
	for _, name := range []string{jsonReportFilename, mdReportFilename} {
		if _, err := os.Stat(name); err == nil {
			t.Fatalf("%s exists, want no -O means no file is ever written", name)
		}
	}
}

func TestRun_OutputFilesInvalid_Exits2WithUsageError(t *testing.T) {
	for _, target := range []string{"yaml", "xml"} {
		t.Run(target, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run([]string{"-O", target}, &stdout, &stderr)
			if got != 2 {
				t.Fatalf("run([-O %s]) = %d, want 2\nstderr: %s", target, got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "not a valid -O value") {
				t.Fatalf("stderr = %q, want it to contain \"not a valid -O value\"", stderr.String())
			}
		})
	}
}

func TestRun_OutputFilesAllComposesWithStdoutFormat(t *testing.T) {
	t.Chdir(t.TempDir())
	withScan(t, findingsReportScan)

	var stdout, stderr bytes.Buffer
	got := run([]string{"-O", "all", "-o", "json"}, &stdout, &stderr)
	if got != 1 {
		t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
	}

	var docs []struct {
		Findings []struct{} `json:"findings"`
	}
	if err := stdjson.Unmarshal(stdout.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, stdout.String())
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1 (one target)", len(docs))
	}
	if len(docs[0].Findings) != 1 {
		t.Fatalf("docs[0].Findings has %d entries, want 1", len(docs[0].Findings))
	}
	for _, name := range []string{jsonReportFilename, mdReportFilename} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("Stat(%s) error = %v, want the file to exist", name, err)
		}
	}
}

func TestRun_OutputFilesWriteFailureExits2OnCleanScan(t *testing.T) {
	t.Chdir(t.TempDir())
	withScan(t, emptyReportScan)

	if err := os.Mkdir(jsonReportFilename, 0o755); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", jsonReportFilename, err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-O", "json"}, &stdout, &stderr); got != 2 {
		t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
	}
}

func TestRun_OutputFilesWriteFailureExits2OverridesFindingsPresent(t *testing.T) {
	t.Chdir(t.TempDir())
	withScan(t, findingsReportScan)

	if err := os.Mkdir(jsonReportFilename, 0o755); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", jsonReportFilename, err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-O", "json"}, &stdout, &stderr); got != 2 {
		t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
	}
}

// Deliberately skips the withScan seam so the real WithWarnFunc wiring is
// what routes the warning, not a test-only substitute.
func TestScanSeamRoutesRealParseWarningsToItsCallback(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte("{not valid json")},
	}

	var got []error
	rep, err := scan(fsys, func(e error) { got = append(got, e) })
	if err != nil {
		t.Fatalf("scan() error = %v, want nil", err)
	}
	if len(got) == 0 {
		t.Errorf("scan() routed no warnings, want >=1 for the malformed settings.json")
	} else if !strings.Contains(got[0].Error(), "settings.json") {
		t.Errorf("scan() warning = %q, want it to name settings.json", got[0].Error())
	}
	if got := rep.UnreadableSources(); got != 0 {
		t.Errorf("UnreadableSources() = %d, want 0 (a malformed but readable source hides nothing)", got)
	}
	if got := rep.UnparsedSources(); got != 1 {
		t.Errorf("UnparsedSources() = %d, want 1 (what the source declared never reached the report)", got)
	}
}

func TestRun_VersionFlagPrintsVersionAndSkipsScan(t *testing.T) {
	scanCalled := false
	withScan(t, func(fs.FS, func(error)) (finding.Report, error) {
		scanCalled = true
		return finding.Report{}, nil
	})
	savedVersion, savedCommit := version, commit
	version, commit = "v0.1.0", "C"
	t.Cleanup(func() { version, commit = savedVersion, savedCommit })

	tests := []struct {
		name string
		args []string
	}{
		{"short flag", []string{"-V"}},
		{"long flag", []string{"--version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanCalled = false
			var stdout, stderr bytes.Buffer
			got := run(tt.args, &stdout, &stderr)
			if got != 0 {
				t.Fatalf("run(%v) = %d, want 0", tt.args, got)
			}
			if want := "agentaudit 0.1.0 (commit: C)\n"; stdout.String() != want {
				t.Fatalf("stdout = %q, want %q", stdout.String(), want)
			}
			if scanCalled {
				t.Fatalf("run(%v) invoked scan, want the version flag to skip scanning entirely", tt.args)
			}
		})
	}

	scanCalled = false
	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 0 {
		t.Fatalf("run(nil) = %d, want 0\nstderr: %s", got, stderr.String())
	}
	if !scanCalled {
		t.Fatal("run without the version flag invoked no scan either, so the zeros asserted above prove nothing")
	}
}
