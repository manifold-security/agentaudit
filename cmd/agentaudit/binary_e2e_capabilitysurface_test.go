package main

import (
	"strings"
	"testing"
)

const capabilitySurfaceFixture = "../../testdata/malicious/claude-capability-surface"

// The shipped binary must surface every category on its own, not only the
// golden's in-process rendering.
func TestBinaryE2E_CapabilitySurfaceReportsEveryCategory(t *testing.T) {
	bin := buildAgentauditBinary(t)
	absFixture := resolveFixture(t, capabilitySurfaceFixture)

	stdout, _, code := runBinary(t, bin, absFixture)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s", code, stdout)
	}

	for _, want := range []string{
		"code-execution:",
		"permissions:",
		"network-access:",
		"sandbox:",
		"hook SessionStart",
		"mcpServer build-tool (stdio)",
		"lspServer toolkit-lang",
		"headers helper for",
		"plugin toolkit-plugin",
		"pluginExecutable sync.sh",
		"sandbox · /var/run/docker.sock",
		"permissionMode · acceptEdits",
		`previewServer web (cwd="apps/web"; env.NODE_ENV="development") · npm run dev`,
		"permission Bash · npm run test:*",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "previewServer attached") {
		t.Errorf("binary stdout reports the url-only preview entry, which runs nothing\nfull stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "permission WebFetch") {
		t.Errorf("binary stdout reports a WebFetch allow entry, want only the shell one\nfull stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "SCAN INCOMPLETE") {
		t.Errorf("binary stdout contains SCAN INCOMPLETE, want a complete scan\nfull stdout:\n%s", stdout)
	}
}
