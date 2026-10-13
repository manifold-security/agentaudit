//go:build !js

package agentaudit_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit"
)

// scanBudget is calibrated for native execution, which is what the build
// constraint above keeps this file to. The syscall/js shim carries the
// branching symlink probe's CLI path past the whole budget on a shared CI
// runner, where measuring it would score the host rather than a regression
// here.
const scanBudget = time.Second

// A wall-clock budget catches an order-of-magnitude regression such as
// superlinear directory walking. It proves no fixed duration for a real
// repository: the margin is this fixture's richness, not a timing proof.
func TestScanCoverageProjectCompletesWithinBudget(t *testing.T) {
	s := agentaudit.New()

	for _, row := range capabilitySurfaceRoots {
		start := time.Now()
		if _, err := scanRow(s, row); err != nil {
			t.Fatalf("scanning %s error = %v", row.root, err)
		}
		if elapsed := time.Since(start); elapsed > scanBudget {
			t.Fatalf("scanning %s took %s, want under %s", row.root, elapsed, scanBudget)
		}
	}
}

func BenchmarkScanCoverageProject(b *testing.B) {
	s := agentaudit.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, row := range capabilitySurfaceRoots {
			if _, err := scanRow(s, row); err != nil {
				b.Fatalf("scanning %s error = %v", row.root, err)
			}
		}
	}
}

// buildBranchingSymlinkFixture builds a real tree that branches at every
// level of symlink indirection: a walker without a visited-set faces
// combinatorial path growth.
func buildBranchingSymlinkFixture(t *testing.T, root string, levels, branching int) {
	t.Helper()

	var dirs []string
	for i := 0; i < levels; i++ {
		name := "level" + string(rune('a'+i))
		dir := root + "/" + name
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(dir+"/leaf.txt", []byte("leaf"), 0o644); err != nil {
			t.Fatalf("write leaf marker in %s: %v", dir, err)
		}
		dirs = append(dirs, name)
	}

	for _, name := range dirs {
		dir := root + "/" + name
		for b := 0; b < branching; b++ {
			for _, target := range dirs {
				if target == name {
					continue
				}
				link := dir + "/to-" + target + "-" + string(rune('0'+b))
				if err := os.Symlink("../"+target, link); err != nil {
					t.Skipf("symlinks unavailable on this platform: %v", err)
				}
			}
		}
	}

	loopArmDir := root + "/" + dirs[len(dirs)-1]
	if err := os.Symlink(".", loopArmDir+"/self-loop"); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
}

// synthesizedClaudeJSON builds n placeholder project blocks in memory, so
// the fixture reads no real $HOME and carries no oauthAccount or machineID.
func synthesizedClaudeJSON(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"projects":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"/repo/project-%05d":{"mcpServers":{"server":{"command":"npx"}}}`, i)
	}
	b.WriteString(`}}`)
	return b.Bytes()
}

// Cost must not grow superlinearly in the number of project blocks
// .claude.json declares. The finding count is the companion proof of
// execution: a ParseGlobal returning nothing early would pass on time alone.
func TestScanGlobal_ManyProjectBlocksStaysWithinScanBudget(t *testing.T) {
	const n = 4000
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: synthesizedClaudeJSON(n)}}

	s := agentaudit.New()
	start := time.Now()
	report, err := s.ScanGlobal(fsys)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if got := len(report.Findings()); got != n {
		t.Fatalf("Findings() len = %d, want %d (one claude.mcp.server per synthesized project)", got, n)
	}
	if elapsed > scanBudget {
		t.Fatalf("ScanGlobal() over %d synthesized project blocks took %s, want under %s (measured overrun — do not widen scanBudget to fix this)", n, elapsed, scanBudget)
	}
}

// scanWithDeadline must not assume the bound it exists to check: a probe
// that gives up proves an overrun as validly as natural completion does.
func scanWithDeadline(t *testing.T, scan func() error, deadline time.Duration) (completed bool, elapsed time.Duration) {
	t.Helper()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- scan() }()

	select {
	case err := <-done:
		elapsed = time.Since(start)
		if err != nil {
			t.Fatalf("scan error = %v", err)
		}
		return true, elapsed
	case <-time.After(deadline):
		return false, deadline
	}
}

// internal/discovery's symlinkResolutionBudget bounds both entry points
// below identically, upstream of whichever fs.FS the caller supplies; what
// this measures is that the bound holds in wall-clock terms, not merely in
// resolution counts. The probe deadline is a multiple of scanBudget so an
// overrun reads as a measured number rather than as a hang.
func TestBranchingSymlinkIndirectionStaysWithinScanBudget(t *testing.T) {
	root := t.TempDir()
	const branchingDirs = 3
	buildBranchingSymlinkFixture(t, root, branchingDirs, 1)

	s := agentaudit.New()
	probeDeadline := 5 * scanBudget

	libraryCompleted, libraryElapsed := scanWithDeadline(t, func() error {
		_, err := s.Scan(os.DirFS(root))
		return err
	}, probeDeadline)

	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("OpenRoot(%s) error = %v", root, err)
	}
	defer r.Close()

	cliCompleted, cliElapsed := scanWithDeadline(t, func() error {
		_, err := s.Scan(r.FS())
		return err
	}, probeDeadline)

	t.Logf("branching symlink fixture (%d dirs, full pairwise symlinks): library path (os.DirFS) completed=%v elapsed=%s; CLI path (os.OpenRoot.FS()) completed=%v elapsed=%s; budget=%s probe deadline=%s",
		branchingDirs, libraryCompleted, libraryElapsed, cliCompleted, cliElapsed, scanBudget, probeDeadline)

	if !libraryCompleted {
		t.Fatalf("library path (os.DirFS) did not complete within the %s probe deadline (%s over the %s budget) — measured overrun, not a reason to widen scanBudget", probeDeadline, probeDeadline, scanBudget)
	}
	if libraryElapsed > scanBudget {
		t.Fatalf("library path (os.DirFS) took %s, want under %s (measured overrun — do not widen scanBudget to fix this)", libraryElapsed, scanBudget)
	}
	if !cliCompleted {
		t.Fatalf("CLI path (os.OpenRoot.FS()) did not complete within the %s probe deadline (%s over the %s budget) — measured overrun, not a reason to widen scanBudget", probeDeadline, probeDeadline, scanBudget)
	}
	if cliElapsed > scanBudget {
		t.Fatalf("CLI path (os.OpenRoot.FS()) took %s, want under %s (measured overrun — do not widen scanBudget to fix this)", cliElapsed, scanBudget)
	}
}
