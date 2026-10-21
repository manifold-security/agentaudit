package main

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"testing"
)

// updateGolden regenerates the goldens in this package's testdata, mirroring
// the reporter packages' own -update idiom.
//
// Run with: go test ./cmd/agentaudit/... -update
var updateGolden = flag.Bool("update", false, "update golden files")

func TestRun_Recursive_MultiProjectPrettyGolden(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{"container": twoProjectContainerFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-r", "container"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	const goldenPath = "testdata/multiproject_pretty.golden"
	if *updateGolden {
		if err := os.WriteFile(goldenPath, stdout.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to generate it)", goldenPath, err)
	}
	if stdout.String() != string(want) {
		t.Fatalf("Write() output mismatch\n--- got ---\n%s\n--- want ---\n%s", stdout.String(), string(want))
	}
}

// A stable display name keeps the golden independent of where the fixture
// lives on disk.
func TestRun_CoverageProjectPrettyGolden(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{
		"coverage-project": os.DirFS("../../testdata/malicious/claude-capability-surface"),
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"coverage-project"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	const goldenPath = "testdata/capability_surface_pretty.golden"
	if *updateGolden {
		if err := os.WriteFile(goldenPath, stdout.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to generate it)", goldenPath, err)
	}
	if stdout.String() != string(want) {
		t.Fatalf("Write() output mismatch\n--- got ---\n%s\n--- want ---\n%s", stdout.String(), string(want))
	}
}
