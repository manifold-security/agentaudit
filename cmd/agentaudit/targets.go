package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/manifold-security/agentaudit"
)

// resolveTargets unions the positional target with scanDirs, keeping one
// entry per filepath.Clean form of a path and a URL as given. An empty value
// is a usage fault: filepath.Clean("") is ".", so accepting one would scan the
// current directory under the guise of a named target.
func resolveTargets(positional, scanDirs []string) ([]string, error) {
	var ordered []string
	seen := make(map[string]struct{})

	add := func(p string) {
		clean := p
		if !isURL(p) {
			clean = filepath.Clean(p)
		}
		if _, dup := seen[clean]; dup {
			return
		}
		seen[clean] = struct{}{}
		ordered = append(ordered, clean)
	}

	for _, p := range positional {
		if p == "" {
			return nil, fmt.Errorf("agentaudit: PATH must not be empty")
		}
	}
	for _, p := range scanDirs {
		if p == "" {
			return nil, fmt.Errorf("agentaudit: --scan-dir value must not be empty")
		}
		if isURL(p) {
			return nil, fmt.Errorf("agentaudit: --scan-dir takes a directory")
		}
	}

	for _, p := range positional {
		add(p)
	}
	for _, p := range scanDirs {
		add(p)
	}

	if len(ordered) == 0 {
		return []string{"."}, nil
	}
	return ordered, nil
}

// openTarget is the only non-test call site in this package naming
// os.OpenRoot, so it stays the single locatable containment seam
// (TestOpenTargetIsTheOnlyOpenRootCallSite). The returned fs.FS refuses a
// symlink whose resolution escapes path, so an adapter-owned source cannot
// pull out-of-tree content into the report; linkFS rides on top to admit
// the in-tree ones a dotfile manager spells absolutely, re-entering every
// rewritten path through the same root.
var openTarget = func(path string) (fs.FS, func() error, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	return newLinkFS(root.FS(), path), root.Close, nil
}

// displayPath keeps a container project's header identical to a plain scan
// of that target rather than rewriting it into "target/.".
func displayPath(target, proj string) string {
	if proj == "." {
		return target
	}
	return filepath.Join(target, proj)
}

// targetBlocks holds the root open only for its own call, so scanning many
// targets never accumulates descriptors (TestRun_ClosesOneRootPerTarget).
func targetBlocks(target string, recursive bool, warn func(error), opts ...agentaudit.Option) (blocks []block, withheld bool, err error) {
	if isURL(target) {
		return urlBlocks(target, recursive, warn, opts)
	}
	fsys, closeRoot, err := openTarget(target)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = closeRoot() }()

	if !recursive {
		rep, err := scan(fsys, warn, opts...)
		if err != nil {
			return nil, false, err
		}
		return []block{{Path: displayPath(target, "."), Report: rep}}, false, nil
	}

	projects, err := scanRecursive(fsys, warn, opts...)
	if err != nil {
		return nil, false, err
	}
	blocks = make([]block, len(projects))
	for i, p := range projects {
		blocks[i] = block{Path: displayPath(target, p.Path), Report: p.Report}
	}
	return blocks, false, nil
}
