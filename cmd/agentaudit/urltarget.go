package main

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/remote"
)

var fetch = remote.Fetch

var fetchTimeout = 120 * time.Second

var urlLimits = remote.Limits{
	Rounds:      8,
	TreeEntries: 2_000_000,
	PathBytes:   160 << 20,
	Files:       8_000,
	RefsBytes:   128 << 20,
	PackBytes:   64 << 20,
	FileBytes:   64 << 20,
	TotalBytes:  192 << 20,
}

// urlScheme takes a scheme of two characters or more, so a drive letter
// such as C://dir stays a path.
var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]+://`)

func isURL(arg string) bool { return urlScheme.MatchString(arg) }

func withoutUserinfo(raw string) string {
	scheme, rest, _ := strings.Cut(raw, "://")
	authority, tail, hasPath := strings.Cut(rest, "/")
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return raw
	}
	shown := scheme + "://***" + authority[at:]
	if hasPath {
		shown += "/" + tail
	}
	return shown
}

func urlBlocks(raw string, recursive bool, warn func(error), opts []agentaudit.Option) ([]block, bool, error) {
	shown := withoutUserinfo(raw)
	u, err := remote.ParseURL(raw)
	if err != nil {
		return nil, false, fmt.Errorf("agentaudit: %s: %w", shown, err)
	}
	fetchOpts := slices.Clip(opts)
	if recursive {
		fetchOpts = append(fetchOpts, agentaudit.WithRecursive())
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	sha, tree, err := fetch(ctx, raw, "", newScanner(warn, fetchOpts), urlLimits)
	if err != nil {
		return nil, false, fmt.Errorf("agentaudit: %s: %w", shown, err)
	}

	display := "github.com/" + u.Owner + "/" + u.Repo
	if len(u.Tree) > 0 {
		display += "/tree/" + strings.Join(u.Tree, "/")
	}
	display += "@" + sha[:12]

	var blocks []block
	if !recursive {
		rep, err := scan(tree, warn, opts...)
		if err != nil {
			return nil, false, err
		}
		blocks = []block{{Path: display, Report: rep}}
	} else {
		projects, err := scanRecursive(tree, warn, opts...)
		if err != nil {
			return nil, false, err
		}
		for _, p := range projects {
			blocks = append(blocks, block{Path: path.Join(display, p.Path), Report: p.Report})
		}
	}
	// Past Seal, Missing names the withheld paths the scan read.
	return blocks, len(tree.Missing()) > 0, nil
}
