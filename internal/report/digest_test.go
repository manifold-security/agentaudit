package report_test

import (
	"regexp"
	"testing"

	"github.com/manifold-security/agentaudit/internal/report"
)

var hexPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestDigest_IsStableAndFormatted(t *testing.T) {
	const rawID = "hook.autostart\x1fhook\x1fSessionStart\x1f\x1fnotify.sh\x1f.claude/settings.json\x1fhooks[0]"

	first := report.Digest(rawID)
	second := report.Digest(rawID)

	if first != second {
		t.Fatalf("Digest(rawID) = %q then %q, want the same value both times", first, second)
	}
	if !hexPattern.MatchString(first) {
		t.Fatalf("Digest(rawID) = %q, want it to match %s", first, hexPattern)
	}
}

func TestDigest_DistinctInputsProduceDistinctDigests(t *testing.T) {
	a := report.Digest("mcp.stdio\x1fmcpServer fs (stdio)\x1fnpx mcp-fs\x1f.mcp.json\x1fmcpServers.fs")
	b := report.Digest("mcp.unpinned-npx-command\x1fmcpServer fs (stdio)\x1fnpx mcp-fs\x1f.mcp.json\x1fmcpServers.fs")

	if a == b {
		t.Fatalf("Digest collapsed two distinct raw ids to the same digest %q", a)
	}
}
