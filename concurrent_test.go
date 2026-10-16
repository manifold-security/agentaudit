package agentaudit_test

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

func concurrentScanFS() fstest.MapFS {
	return fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"notify.sh"}]}]}}`)},
		".mcp.json":             &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","mcp-fs"]},"broken":7}}`)},
	}
}

// One Scanner serves Scan and ScanRecursive from two goroutines at once and
// each returns what it returns alone, with every warning still delivered.
func TestOneScannerRunsScanAndScanRecursiveConcurrently(t *testing.T) {
	fsys := concurrentScanFS()

	var sequentialWarnings atomic.Int64
	sequential := agentaudit.New(agentaudit.WithWarnFunc(func(error) { sequentialWarnings.Add(1) }))
	wantReport, err := sequential.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	wantProjects, err := sequential.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	if len(wantReport.Findings()) == 0 || sequentialWarnings.Load() == 0 {
		t.Fatalf("sequential run gave %d finding(s) and %d warning(s), want both non-zero so the comparison below is not vacuous", len(wantReport.Findings()), sequentialWarnings.Load())
	}

	var warnings atomic.Int64
	scanner := agentaudit.New(agentaudit.WithWarnFunc(func(error) { warnings.Add(1) }))
	var (
		wg                  sync.WaitGroup
		gotReport           agentaudit.Report
		gotProjects         []agentaudit.ProjectReport
		scanErr, recurseErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		gotReport, scanErr = scanner.Scan(fsys)
	}()
	go func() {
		defer wg.Done()
		gotProjects, recurseErr = scanner.ScanRecursive(fsys)
	}()
	wg.Wait()

	if scanErr != nil || recurseErr != nil {
		t.Fatalf("concurrent Scan() error = %v, ScanRecursive() error = %v, want nil", scanErr, recurseErr)
	}
	if !reflect.DeepEqual(gotReport, wantReport) {
		t.Fatalf("concurrent Scan() = %+v, want the sequential %+v", gotReport, wantReport)
	}
	if !reflect.DeepEqual(gotProjects, wantProjects) {
		t.Fatalf("concurrent ScanRecursive() = %+v, want the sequential %+v", gotProjects, wantProjects)
	}
	if warnings.Load() != sequentialWarnings.Load() {
		t.Fatalf("WarnFunc called %d time(s) concurrently, want the sequential %d", warnings.Load(), sequentialWarnings.Load())
	}
}
