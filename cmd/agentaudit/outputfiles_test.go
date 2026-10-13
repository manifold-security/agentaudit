package main

import (
	stdjson "encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// failingCloseWriter gives a test a Close failure no cooperative *os.File
// offers.
type failingCloseWriter struct{}

func (failingCloseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (failingCloseWriter) Close() error                { return errors.New("injected close failure") }

func outputFilesFixtureReport() finding.Report {
	f := finding.Finding{
		RuleID:     "test.rule",
		Categories: []finding.Category{"test"},
		Capability: finding.Capability{
			Entity:     ir.EnvVar{Name: "X", Value: "y"},
			Provenance: finding.Provenance{File: "settings.json", Key: "env.X"},
		},
	}
	return finding.NewReport([]finding.Finding{f})
}

func TestWriteReportFiles_MultipleBlocksWritesOneArrayAndConcatenatedMarkdown(t *testing.T) {
	t.Chdir(t.TempDir())

	blocks := []block{
		{Path: "a", Report: outputFilesFixtureReport()},
		{Path: "b", Report: outputFilesFixtureReport()},
	}

	if err := writeReportFiles("all", blocks, ""); err != nil {
		t.Fatalf("writeReportFiles() error = %v, want nil", err)
	}

	jsonData, err := os.ReadFile(jsonReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", jsonReportFilename, err)
	}
	var docs []struct {
		Path string `json:"path"`
	}
	if err := stdjson.Unmarshal(jsonData, &docs); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", jsonReportFilename, err)
	}
	if len(docs) != 2 {
		t.Fatalf("len(docs) = %d, want 2", len(docs))
	}
	if docs[0].Path != "a" || docs[1].Path != "b" {
		t.Fatalf("docs paths = [%q, %q], want [\"a\", \"b\"] in block order", docs[0].Path, docs[1].Path)
	}

	mdData, err := os.ReadFile(mdReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
	}
	md := string(mdData)
	if got := strings.Count(md, "# agentaudit"); got != 2 {
		t.Fatalf("%s has %d H1 headers, want 2 (one per block)", mdReportFilename, got)
	}
	hA, hB := strings.Index(md, "# agentaudit · a\n"), strings.Index(md, "# agentaudit · b\n")
	if hA == -1 || hB == -1 {
		t.Fatalf("%s = %q, want H1 headers identifying \"a\" and \"b\"", mdReportFilename, md)
	}
	if hA > hB {
		t.Fatalf("%s has the \"b\" H1 before the \"a\" H1, want block order preserved", mdReportFilename)
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error = %v", err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory contains %v, want exactly the two default-named files", names)
	}
}

func TestWriteReportFiles_JSONCreatesDefaultNamedFile(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := writeReportFiles("json", []block{{Path: ".", Report: outputFilesFixtureReport()}}, ""); err != nil {
		t.Fatalf("writeReportFiles() error = %v, want nil", err)
	}

	data, err := os.ReadFile(jsonReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", jsonReportFilename, err)
	}
	var docs []struct {
		Findings []struct{} `json:"findings"`
	}
	if err := stdjson.Unmarshal(data, &docs); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", jsonReportFilename, err)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1", len(docs))
	}
	if len(docs[0].Findings) != 1 {
		t.Fatalf("docs[0].Findings has %d entries, want 1", len(docs[0].Findings))
	}
}

func TestWriteReportFiles_MDCreatesDefaultNamedFile(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := writeReportFiles("md", []block{{Path: ".", Report: outputFilesFixtureReport()}}, ""); err != nil {
		t.Fatalf("writeReportFiles() error = %v, want nil", err)
	}

	data, err := os.ReadFile(mdReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
	}
	if !strings.HasPrefix(string(data), "# agentaudit") {
		t.Fatalf("%s content = %q, want it to start with \"# agentaudit\"", mdReportFilename, string(data))
	}
}

func TestWriteReportFiles_AllWritesBothFilesInOrder(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := writeReportFiles("all", []block{{Path: ".", Report: outputFilesFixtureReport()}}, ""); err != nil {
		t.Fatalf("writeReportFiles() error = %v, want nil", err)
	}

	for _, name := range []string{jsonReportFilename, mdReportFilename} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("Stat(%s) error = %v, want the file to exist", name, err)
		}
	}
}

func TestWriteReportFiles_OverwritesExistingFileSilently(t *testing.T) {
	t.Chdir(t.TempDir())

	const sentinel = "leftover content from a previous run"
	if err := os.WriteFile(jsonReportFilename, []byte(sentinel), 0o644); err != nil {
		t.Fatalf("WriteFile(sentinel) error = %v", err)
	}

	if err := writeReportFiles("json", []block{{Path: ".", Report: outputFilesFixtureReport()}}, ""); err != nil {
		t.Fatalf("writeReportFiles() error = %v, want nil", err)
	}

	data, err := os.ReadFile(jsonReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", jsonReportFilename, err)
	}
	if strings.Contains(string(data), sentinel) {
		t.Fatalf("%s still contains sentinel content, want it overwritten", jsonReportFilename)
	}
	if !strings.Contains(string(data), "findings") {
		t.Fatalf("%s content = %q, want real JSON report content", jsonReportFilename, string(data))
	}
}

func TestWriteReportFiles_JSONFailureStopsBeforeMD(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := os.Mkdir(jsonReportFilename, 0o755); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", jsonReportFilename, err)
	}

	err := writeReportFiles("all", []block{{Path: ".", Report: outputFilesFixtureReport()}}, "")
	if err == nil {
		t.Fatalf("writeReportFiles() error = nil, want a non-nil error")
	}
	if _, statErr := os.Stat(mdReportFilename); statErr == nil {
		t.Fatalf("%s exists, want the md file never attempted after the json failure", mdReportFilename)
	}
}

func TestWriteReportFile_CloseErrorTreatedAsWriteError(t *testing.T) {
	original := createFile
	createFile = func(string) (io.WriteCloser, error) { return failingCloseWriter{}, nil }
	t.Cleanup(func() { createFile = original })

	err := writeReportFile("ignored", func(io.Writer) error { return nil })
	if err == nil {
		t.Fatalf("writeReportFile() error = nil, want the injected Close failure to surface")
	}
	if !strings.Contains(err.Error(), "closing") {
		t.Fatalf("writeReportFile() error = %q, want it to name the closing step", err.Error())
	}
}

func TestWriteReportFiles_MDFailureAfterJSONSucceeds(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := os.Mkdir(mdReportFilename, 0o755); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", mdReportFilename, err)
	}

	err := writeReportFiles("all", []block{{Path: ".", Report: outputFilesFixtureReport()}}, "")
	if err == nil {
		t.Fatalf("writeReportFiles() error = nil, want a non-nil error")
	}

	data, statErr := os.ReadFile(jsonReportFilename)
	if statErr != nil {
		t.Fatalf("ReadFile(%s) error = %v, want the json file to exist with content", jsonReportFilename, statErr)
	}
	if !strings.Contains(string(data), "findings") {
		t.Fatalf("%s content = %q, want real JSON report content", jsonReportFilename, string(data))
	}
}
