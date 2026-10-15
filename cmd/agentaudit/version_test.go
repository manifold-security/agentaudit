package main

import (
	"runtime/debug"
	"testing"
)

func stampedBuildInfo(mainVersion, revision string) func() (*debug.BuildInfo, bool) {
	info := &debug.BuildInfo{Main: debug.Module{Version: mainVersion}}
	if revision != "" {
		info.Settings = []debug.BuildSetting{{Key: "vcs.revision", Value: revision}}
	}
	return func() (*debug.BuildInfo, bool) { return info, true }
}

func noBuildInfo() (*debug.BuildInfo, bool) { return nil, false }

func TestVersionLine(t *testing.T) {
	otherRelease := stampedBuildInfo("v9.9.9", "R")
	tests := []struct {
		name      string
		ldVersion string
		ldCommit  string
		read      func() (*debug.BuildInfo, bool)
		want      string
	}{
		{"ldflags tag and commit win over the build info", "v0.1.0", "C", otherRelease, "0.1.0 (commit: C)"},
		{"ldflags version without a commit", "0.1.0", "", otherRelease, "0.1.0"},
		{"ldflags dev over a tagged build info", "dev", "", otherRelease, "dev"},
		{"ldflags leading v before a non-digit is kept", "vnext", "", otherRelease, "vnext"},
		{"ldflags commit without an ldflags version", "", "C", stampedBuildInfo("v0.1.0", "R"), "0.1.0 (commit: R)"},
		{"build info tag and revision", "", "", stampedBuildInfo("v0.1.0", "R"), "0.1.0 (commit: R)"},
		{"build info pre-release tag", "", "", stampedBuildInfo("v0.1.0-rc.1", "R"), "0.1.0-rc.1 (commit: R)"},
		{"build info tag without a revision", "", "", stampedBuildInfo("v0.1.0", ""), "0.1.0"},
		{"build info devel", "", "", stampedBuildInfo("(devel)", "R"), "dev"},
		{"build info empty version", "", "", stampedBuildInfo("", "R"), "dev"},
		{"build info unavailable", "", "", noBuildInfo, "dev"},
		{"build info dirty tag", "", "", stampedBuildInfo("v0.1.0+dirty", "R"), "dev"},
		{"pseudo-version with no tag", "", "", stampedBuildInfo("v0.0.0-20261014213517-0ad9bbcb3d6b", "R"), "dev"},
		{"pseudo-version after a tag", "", "", stampedBuildInfo("v0.1.1-0.20261014213517-0ad9bbcb3d6b", "R"), "dev"},
		{"pseudo-version on a pre-release base", "", "", stampedBuildInfo("v0.1.0-rc.1.0.20261014213517-0ad9bbcb3d6b", "R"), "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionLine(tt.ldVersion, tt.ldCommit, tt.read); got != tt.want {
				t.Fatalf("versionLine(%q, %q, read) = %q, want %q", tt.ldVersion, tt.ldCommit, got, tt.want)
			}
		})
	}
}
