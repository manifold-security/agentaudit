package main

import (
	"fmt"
	"regexp"
	"runtime/debug"
)

// version and commit are stamped with -ldflags -X; when version is empty,
// versionLine reads both from the build info instead.
var version, commit string

var semverTag = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// pseudoSuffix takes a dot as well as a dash before the timestamp: the
// post-tag form is v0.1.1-0.<timestamp>-<hash>.
var pseudoSuffix = regexp.MustCompile(`[-.]\d{14}-[0-9a-f]{12}$`)

func versionLine(ldVersion, ldCommit string, read func() (*debug.BuildInfo, bool)) string {
	if ldVersion != "" {
		return displayVersion(ldVersion, ldCommit)
	}
	info, ok := read()
	if !ok || !semverTag.MatchString(info.Main.Version) || pseudoSuffix.MatchString(info.Main.Version) {
		return "dev"
	}
	var revision string
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
	}
	return displayVersion(info.Main.Version, revision)
}

func displayVersion(v, sha string) string {
	if len(v) > 1 && v[0] == 'v' && '0' <= v[1] && v[1] <= '9' {
		v = v[1:]
	}
	if sha == "" {
		return v
	}
	return fmt.Sprintf("%s (commit: %s)", v, sha)
}
