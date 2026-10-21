package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fixture whose rules have to fire is registered in the root package's
// capabilitySurfaceRoots. Its
// TestEveryEmbeddedRuleFiresAcrossCapabilitySurface fails by rule id when one
// of them does not.
const (
	codexCapabilitySurfaceFixture = "../../testdata/malicious/codex-capability-surface"
	codexUnattendedFixture        = "../../testdata/malicious/codex-unattended"
	codexMalformedFixture         = "../../testdata/malicious/codex-malformed"
	codexPermissionProfileFixture = "../../testdata/malicious/codex-permission-profiles"
	codexFullAccessProfileFixture = "../../testdata/malicious/codex-full-access-profile"
	codexNetworkReachFixture      = "../../testdata/malicious/codex-network-reach"
	codexShadowedProfileFixture   = "../../testdata/malicious/codex-shadowed-profile"
)

func TestBinaryE2E_CodexSandboxGrantsReachTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexCapabilitySurfaceFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"(codex)",
		"sandbox readwrite · ~/.ssh",
		"sandbox readwrite · ~/.aws",
		"networkPolicy default · true",
		".codex/config.toml:sandbox_workspace_write.writable_roots[0]",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "SCAN INCOMPLETE") {
		t.Errorf("binary stdout reports an incomplete scan\nfull stdout:\n%s", stdout)
	}
}

// Both hook surfaces reach the shipped binary, and a handler Codex skips
// stays out of the report its runnable sibling reaches.
func TestBinaryE2E_CodexHooksReachTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexCapabilitySurfaceFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"./scripts/warm-cache.sh · .codex/config.toml:hooks.SessionStart[0].hooks[0]",
		"./scripts/release-gate.sh · .codex/hooks.json:hooks.PreToolUse[0].hooks[0]",
		".codex/hooks.json:hooks.PreToolUse[0].hooks[0].commandWindows",
		`mcp_tool server="release-index" tool="record_change" · .codex/hooks.json:hooks.PostToolUse[0].hooks[0]`,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Confirm the command stays inside the workspace.") {
		t.Errorf("binary stdout reports a prompt handler Codex skips\nfull stdout:\n%s", stdout)
	}
}

// Each MCP server reaches the shipped binary with what it runs on connect and
// the local variables it receives, while a disabled server and a variable
// sourced from a remote executor stay out of the report their siblings reach.
func TestBinaryE2E_CodexMCPServersReachTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexCapabilitySurfaceFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"mcpServer release-index (stdio) · npx -y @release/index-server · .codex/config.toml:mcp_servers.release-index",
		"mcpServer docs-search (http) · https://mcp.example.test/mcp · .codex/config.toml:mcp_servers.docs-search",
		`headers helper for url="https://mcp.example.test/mcp" · ./scripts/mcp-headers.sh · .codex/config.toml:mcp_servers.docs-search.http_headers_helper`,
		`env sent to url="https://mcp.example.test/mcp" · DOCS_SEARCH_TOKEN · .codex/config.toml:mcp_servers.docs-search.bearer_token_env_var`,
		"RELEASE_TEAM_ID · .codex/config.toml:mcp_servers.docs-search.env_http_headers.X-Team-Id",
		`env sent to command="./scripts/changelog-server.sh" · CHANGELOG_TOKEN · .codex/config.toml:mcp_servers.changelog.env_vars[0]`,
		"SIGNING_KEY · .codex/config.toml:mcp_servers.changelog.env_vars[1]",
		`mcpServer dual-index (stdio; url="https://index.example.test/mcp") · ./scripts/index-server.sh · .codex/config.toml:mcp_servers.dual-index`,
		`env sent to url="https://index.example.test/mcp" · INDEX_TOKEN · .codex/config.toml:mcp_servers.dual-index.bearer_token_env_var`,
		`mcpServer dual-index (stdio) env sent to command="./scripts/index-server.sh" · INDEX_CACHE_DIR · .codex/config.toml:mcp_servers.dual-index.env_vars[0]`,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	for _, absent := range []string{"mcp_servers.archive", "EXECUTOR_TOKEN"} {
		if strings.Contains(stdout, absent) {
			t.Errorf("binary stdout reports %q, which is disabled or read from the remote executor, not this machine\nfull stdout:\n%s", absent, stdout)
		}
	}
}

// The scripts a skill bundles reach the shipped binary located by their own
// paths, from a skill directly beneath the skills root and from one below a
// category directory alike, while the reference file beside them stays out.
func TestBinaryE2E_CodexSkillScriptsReachTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexCapabilitySurfaceFixture)

	stdout, stderr, code := runBinary(t, bin, tree, "-v")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"bundledPayload .sh +x · - · .agents/skills/release-notes/scripts/collect-changes.sh",
		"bundledPayload .py · - · .agents/skills/ops/rotate-keys/scripts/lib/rotate.py",
		"codex.payload.skill-script",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "references/style.md") {
		t.Errorf("binary stdout reports a reference file as a bundled script\nfull stdout:\n%s", stdout)
	}
}

// A refused skill-folder link reaches stderr and the footer's unreadable
// count, while the real skill beside it is still reported. The target stays
// inside the scanned tree so the adapter's refusal is what answers, not the
// containment root.
func TestBinaryE2E_CodexSymlinkedSkillFolderIsNamedRatherThanSilentlyDropped(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	for name, body := range map[string]string{
		".agents/skills/ship/SKILL.md":        "---\nname: ship\ndescription: ship\n---\n",
		".agents/skills/ship/scripts/ship.sh": "#!/bin/sh\n",
		"shared/linked/SKILL.md":              "---\nname: linked\ndescription: linked\n---\n",
		"shared/linked/scripts/linked.sh":     "#!/bin/sh\n",
	} {
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatalf("building fixture: %v", err)
		}
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatalf("building fixture: %v", err)
		}
	}
	link := filepath.Join(root, ".agents", "skills", "linked")
	if err := os.Symlink(filepath.Join("..", "..", "shared", "linked"), link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the sibling skill's script is a finding)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, ".agents/skills/ship/scripts/ship.sh") {
		t.Errorf("binary stdout missing the sibling skill's script\nfull stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "linked.sh") {
		t.Errorf("binary stdout reports a script behind the refused link\nfull stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, ".agents/skills/linked") {
		t.Errorf("binary stderr does not name the refused link\nstderr:\n%s", stderr)
	}
	if got := parseUnreadableCount(t, stdout); got != 1 {
		t.Errorf("footer counts %d unreadable sources, want 1\nstdout:\n%s", got, stdout)
	}
}

// A key no parser here reads leaves the document fully read: reporting it as
// partly parsed would put a degradation banner over a complete scan.
func TestBinaryE2E_CodexUnreadKeysLeaveTheScanComplete(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexCapabilitySurfaceFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("binary stderr warned about a key it reads past\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "33 capabilities · 4 files · 6 categories") {
		t.Errorf("binary stdout missing the fixture's own tally\nfull stdout:\n%s", stdout)
	}
}

// The blanket policy and the confinement it drops are one project's whole
// declaration, so both have to reach the artifact users run, and the
// web_search mode beside them reaches no finding.
func TestBinaryE2E_CodexUnattendedProjectReachesTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexUnattendedFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"sandbox mode · danger-full-access",
		"permissionMode · never",
		".codex/config.toml:approval_policy",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if unwanted := "networkPolicy default · live"; strings.Contains(stdout, unwanted) {
		t.Errorf("binary stdout reports %q, which declares no reach\nfull stdout:\n%s", unwanted, stdout)
	}
}

// A document the decoder stopped on leaves the scan with nothing to report,
// so stderr and the report have to name the source and the exit code has to
// fail, or the run reads as a clean bill of health over a config nothing
// parsed.
func TestBinaryE2E_CodexMalformedConfigIsNamedRatherThanSilentlyClean(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexMalformedFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the malformed config leaves the scan incomplete)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, ".codex/config.toml") {
		t.Errorf("binary stderr does not name the source it could not parse\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Errorf("binary stdout must name the malformed source as unparsed\nfull stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "unreadable source") {
		t.Errorf("binary stdout must not call a source it did read unreadable\nfull stdout:\n%s", stdout)
	}
}

// The profile model is a second permission syntax, and a repository that
// writes its posture that way has to reach the artifact users run.
func TestBinaryE2E_CodexPermissionProfileGrantsReachTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexPermissionProfileFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"(codex)",
		"sandbox workspace_root · ~/code/app",
		"sandbox write · ~/.local/bin",
		"sandbox read · ~/.aws/credentials",
		"sandbox read · ~/.ssh",
		"networkPolicy default · enabled",
		"networkPolicy pattern · api.example.com",
		"sandbox · /var/run/docker.sock",
		".codex/config.toml:permissions.project-edit.workspace_roots.~/code/app",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "sandbox write · .") {
		t.Errorf("binary stdout reports a :workspace_roots write key that is neither absolute nor home-anchored\nfull stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "SCAN INCOMPLETE") {
		t.Errorf("binary stdout reports an incomplete scan\nfull stdout:\n%s", stdout)
	}
}

// A denied entry and a key no parser here reads leave the document fully
// read, and the tally is what catches a denied domain that became a grant.
func TestBinaryE2E_CodexDeniedProfileEntriesLeaveTheScanComplete(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexPermissionProfileFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("binary stderr warned about a key it reads past\nstderr:\n%s", stderr)
	}
	if denied := "tracking.example.net"; strings.Contains(stdout, denied) {
		t.Errorf("binary stdout reports %q, which the profile denies\nfull stdout:\n%s", denied, stdout)
	}
	if !strings.Contains(stdout, "7 capabilities · 1 file · 3 categories") {
		t.Errorf("binary stdout missing the fixture's own tally\nfull stdout:\n%s", stdout)
	}
}

// The built-in that drops the sandbox is reachable both as the selected
// profile and as the base another profile extends, and each declaration
// carries the key that made it.
func TestBinaryE2E_CodexFullAccessProfileReachesTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexFullAccessProfileFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"permissionMode · :danger-full-access",
		".codex/config.toml:default_permissions",
		".codex/config.toml:permissions.release.extends",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
}

// The egress keys are spelled both in the proxy table and under a permission
// profile, and a repository writing either one has to reach the artifact
// users run.
func TestBinaryE2E_CodexNetworkReachReachesTheRealBinary(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexNetworkReachFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"(codex)",
		"networkPolicy pattern · **.example.com",
		"sandbox · /var/run/docker.sock",
		".codex/config.toml:features.network_proxy.allow_local_binding",
		".codex/config.toml:features.network_proxy.dangerously_allow_all_unix_sockets",
		".codex/config.toml:features.network_proxy.dangerously_allow_non_loopback_proxy",
		".codex/config.toml:permissions.release.network.allow_local_binding",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "SCAN INCOMPLETE") {
		t.Errorf("binary stdout reports an incomplete scan\nfull stdout:\n%s", stdout)
	}
}

// A denied entry, a listener address no parser here reads and a web-search
// allowlist all leave the document fully read, and the tally is what
// catches a denial that became a grant.
func TestBinaryE2E_CodexDeniedProxyEntriesLeaveTheScanComplete(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexNetworkReachFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("binary stderr warned about a key it reads past\nstderr:\n%s", stderr)
	}
	for _, unwanted := range []string{"tracking.example.net", "/tmp/old.sock", "127.0.0.1:3128", "docs.example.org"} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("binary stdout reports %q, which no grant declares\nfull stdout:\n%s", unwanted, stdout)
		}
	}
	if !strings.Contains(stdout, "8 capabilities · 1 file · 2 categories") {
		t.Errorf("binary stdout missing the fixture's own tally\nfull stdout:\n%s", stdout)
	}
}

// A profile written beside a sandbox_mode reaches no finding in the shipped
// binary. The proxy table spelling the same egress guards is what proves the
// suppression stops at the profile prefix rather than at the key names.
func TestBinaryE2E_CodexProfileBesideASandboxModeReachesNoFinding(t *testing.T) {
	bin := buildAgentauditBinary(t)
	tree := resolveFixture(t, codexShadowedProfileFixture)

	stdout, stderr, code := runBinary(t, bin, tree)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	for _, want := range []string{
		"sandbox mode · danger-full-access",
		"permissionMode · never",
		"mcpServer release-index (stdio) · npx -y @release/index-server",
		".codex/config.toml:features.network_proxy.allow_local_binding",
		".codex/config.toml:features.network_proxy.dangerously_allow_all_unix_sockets",
		".codex/config.toml:features.network_proxy.dangerously_allow_non_loopback_proxy",
		"networkPolicy pattern · proxy.example.com",
		"sandbox · /var/run/proxy.sock",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	for _, absent := range []string{
		"permissions.release",
		".codex/config.toml:default_permissions",
		"permissionMode · :danger-full-access",
		"sandbox workspace_root · ~/code/app",
		"sandbox read · ~/.aws/credentials",
		"sandbox write · ~/.local/bin",
		"networkPolicy default · enabled",
		"networkPolicy pattern · api.example.com",
		"sandbox · /var/run/docker.sock",
	} {
		if strings.Contains(stdout, absent) {
			t.Errorf("binary stdout reports %q, which the sandbox_mode beside it leaves unapplied\nfull stdout:\n%s", absent, stdout)
		}
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("binary stderr warned about a key it reads past\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "8 capabilities · 1 file · 4 categories") {
		t.Errorf("binary stdout missing the fixture's own tally\nfull stdout:\n%s", stdout)
	}
}
