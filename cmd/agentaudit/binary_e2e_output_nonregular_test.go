package main

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const nonRegularRefusal = "exists and is not a regular file, refusing to write through it"

var outputFileModes = []struct {
	flag, name, prefix string
}{
	{flag: "json", name: jsonReportFilename, prefix: "["},
	{flag: "md", name: mdReportFilename, prefix: "# agentaudit"},
}

func writeSentinel(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("SENTINEL\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertSentinel(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != "SENTINEL\n" {
		t.Fatalf("%s = %q, want it untouched", path, data)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

// A non-regular file planted at a report file's name is refused rather than
// written through, and the report still reaches stdout.
func TestBinaryE2E_OutputFileRefusesANonRegularName(t *testing.T) {
	bin := buildAgentauditBinary(t)

	rows := []struct {
		name  string
		plant func(t *testing.T, root, report string) (untouched func(t *testing.T))
	}{
		{"link to an existing file outside the scanned directory", func(t *testing.T, root, report string) func(t *testing.T) {
			outside := filepath.Join(root, "outside.txt")
			writeSentinel(t, outside)
			symlink(t, "../outside.txt", report)
			return func(t *testing.T) { assertSentinel(t, outside) }
		}},
		{"dangling link to an outside path", func(t *testing.T, root, report string) func(t *testing.T) {
			outside := filepath.Join(root, "created.txt")
			symlink(t, "../created.txt", report)
			return func(t *testing.T) {
				if _, err := os.Lstat(outside); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("Lstat(%s) error = %v, want fs.ErrNotExist", outside, err)
				}
			}
		}},
		{"link to another file in the scanned directory", func(t *testing.T, root, report string) func(t *testing.T) {
			notes := filepath.Join(filepath.Dir(report), "notes.txt")
			writeSentinel(t, notes)
			symlink(t, "notes.txt", report)
			return func(t *testing.T) { assertSentinel(t, notes) }
		}},
		{"directory", func(t *testing.T, root, report string) func(t *testing.T) {
			if err := os.Mkdir(report, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", report, err)
			}
			return func(t *testing.T) {
				entries, err := os.ReadDir(report)
				if err != nil || len(entries) != 0 {
					t.Fatalf("ReadDir(%s) = %d entries, %v; want an empty directory", report, len(entries), err)
				}
			}
		}},
		{"named pipe", func(t *testing.T, root, report string) func(t *testing.T) {
			if out, err := exec.Command("mkfifo", report).CombinedOutput(); err != nil {
				t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
			}
			return func(t *testing.T) {
				info, err := os.Lstat(report)
				if err != nil || info.Mode().Type() != fs.ModeNamedPipe {
					t.Fatalf("Lstat(%s) = %v, %v; want the named pipe left in place", report, info, err)
				}
			}
		}},
		{"socket", func(t *testing.T, root, report string) func(t *testing.T) {
			t.Chdir(filepath.Dir(report))
			ln, err := net.Listen("unix", filepath.Base(report))
			if err != nil {
				t.Fatalf("listen on %s: %v", report, err)
			}
			t.Cleanup(func() { ln.Close() })
			return func(t *testing.T) {
				info, err := os.Lstat(report)
				if err != nil || info.Mode().Type() != fs.ModeSocket {
					t.Fatalf("Lstat(%s) = %v, %v; want the socket left in place", report, info, err)
				}
			}
		}},
	}

	for _, mode := range outputFileModes {
		for _, r := range rows {
			t.Run(mode.flag+"/"+r.name, func(t *testing.T) {
				root := t.TempDir()
				repo := filepath.Join(root, "repo")
				if err := os.Mkdir(repo, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", repo, err)
				}
				untouched := r.plant(t, root, filepath.Join(repo, mode.name))

				out, errOut, code := runBinary(t, bin, repo, "-O", mode.flag)
				untouched(t)
				if code != 2 {
					t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
				}
				var refusals []string
				for _, line := range strings.Split(errOut, "\n") {
					if strings.Contains(line, nonRegularRefusal) {
						refusals = append(refusals, line)
					}
				}
				if len(refusals) != 1 || strings.Count(refusals[0], mode.name) != 1 {
					t.Fatalf("stderr refusals = %q, want one line naming %s once\nstderr:\n%s", refusals, mode.name, errOut)
				}
				if !strings.Contains(out, "agentaudit · .") {
					t.Fatalf("stdout = %q, want the report on stdout", out)
				}
			})
		}
	}
}

// A report name Lstat cannot read is refused with that error, not opened: on
// darwin an ACL can deny readattr on a symbolic link that open(2) still
// follows. The scan targets another directory because discovery of the
// current one stops at the same link.
func TestBinaryE2E_OutputFileRefusesANameLstatCannotRead(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("needs darwin's chmod +a to deny readattr on a link; GOOS=%s", runtime.GOOS)
	}
	bin := buildAgentauditBinary(t)

	for _, mode := range outputFileModes {
		t.Run(mode.flag, func(t *testing.T) {
			root := t.TempDir()
			repo := filepath.Join(root, "repo")
			for _, dir := range []string{repo, filepath.Join(root, "other")} {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", dir, err)
				}
			}
			outside := filepath.Join(root, "outside.txt")
			writeSentinel(t, outside)
			report := filepath.Join(repo, mode.name)
			symlink(t, "../outside.txt", report)
			if out, err := exec.Command("chmod", "-h", "+a", "everyone deny readattr", report).CombinedOutput(); err != nil {
				t.Fatalf("chmod -h +a %s: %v (%s)", report, err, out)
			}

			out, errOut, code := runBinary(t, bin, repo, "-O", mode.flag, "../other")
			assertSentinel(t, outside)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			if !strings.Contains(errOut, "lstat "+mode.name) {
				t.Fatalf("stderr = %q, want the lstat error for %s", errOut, mode.name)
			}
		})
	}
}

// The refusal spares an ordinary report name, and the clean scan exits 0.
func TestBinaryE2E_OutputFileReplacesARegularReportAndCreatesAMissingOne(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, mode := range outputFileModes {
		for _, c := range []struct {
			name  string
			stale bool
		}{{"stale regular report", true}, {"missing report", false}} {
			t.Run(mode.flag+"/"+c.name, func(t *testing.T) {
				repo := t.TempDir()
				report := filepath.Join(repo, mode.name)
				if c.stale {
					writeSentinel(t, report)
				}

				out, errOut, code := runBinary(t, bin, repo, "-O", mode.flag)
				if code != 0 {
					t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
				}
				info, err := os.Lstat(report)
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("Lstat(%s) = %v, %v; want a regular file", report, info, err)
				}
				data, err := os.ReadFile(report)
				if err != nil {
					t.Fatalf("read %s: %v", report, err)
				}
				if !strings.HasPrefix(string(data), mode.prefix) {
					t.Fatalf("%s starts %q, want the %s report", report, data[:min(len(data), 40)], mode.flag)
				}
			})
		}
	}
}
