package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/manifold-security/agentaudit/adapter"
)

const (
	noGlobalConfigLine         = "no user-level agent config found"
	unreadableGlobalConfigLine = "user-level agent config could not be read"
)

func emptyGlobalLine(unreadable bool) string {
	if unreadable {
		return unreadableGlobalConfigLine
	}
	return noGlobalConfigLine
}

type globalSpec struct {
	base  adapter.Base
	allow map[string]bool
}

// globalSpecs derives one globalSpec per distinct Base, unioning adapters
// that share it. Calling registry.Adapters here instead would put the
// derivation behind a seam no stub adapter can reach. Each entry is joined
// onto a resolved Base, so a traversal segment would reach outside the
// target the user asked for: a declaration error, never a cleaned path.
func globalSpecs(adapters []adapter.Adapter) ([]globalSpec, error) {
	var specs []globalSpec
	index := map[adapter.Base]int{}

	for _, a := range adapters {
		gs, ok := a.(adapter.GlobalScoped)
		if !ok {
			continue
		}
		cfg := gs.GlobalConfig()

		i, seen := index[cfg.Base]
		if !seen {
			i = len(specs)
			index[cfg.Base] = i
			specs = append(specs, globalSpec{base: cfg.Base, allow: map[string]bool{}})
		}
		for _, entry := range cfg.Entries {
			// fs.ValidPath admits ".", which names the Base rather than
			// anything under it: the mask would then admit only the root
			// while anyPresent still reports present, so the block renders
			// clean over a config nothing read.
			if entry == "." || !fs.ValidPath(entry) {
				return nil, fmt.Errorf("agentaudit: %s declares global config entry %q, want a relative path with no %q or %q segment", a.Agent(), entry, ".", "..")
			}
			specs[i].allow[entry] = true
		}
	}
	return specs, nil
}

func globalOnlyConflict(positional, scanDirs []string, recursive bool) error {
	var conflict string
	switch {
	case len(positional) > 0:
		conflict = "PATH"
	case len(scanDirs) > 0:
		conflict = "--scan-dir"
	case recursive:
		conflict = "-r/--recursive"
	default:
		return nil
	}
	return fmt.Errorf("agentaudit: --global-config scans only the user-level config and cannot be combined with %s", conflict)
}

// resolveBase maps a symbolic Base to the absolute directory it names.
func resolveBase(base adapter.Base) (string, error) {
	switch base {
	case adapter.BaseHome:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("agentaudit: resolving global config base: %w", err)
		}
		abs, err := filepath.Abs(home)
		if err != nil {
			return "", fmt.Errorf("agentaudit: resolving global config base: %w", err)
		}
		return abs, nil
	default:
		return "", fmt.Errorf("agentaudit: unknown global config base %q", base)
	}
}

// globalBlocks mentions a Base only when a declared entry is present, not on
// the flag alone. A resolution or open fault is warned and skipped rather
// than propagated: a silent skip would read as a false clean. A Base that
// exists but will not open sets unreadable, so an empty run over it is not
// reported as absent.
func globalBlocks(adapters []adapter.Adapter, warn func(error)) (blocks []block, unreadable bool, err error) {
	specs, err := globalSpecs(adapters)
	if err != nil {
		return nil, false, err
	}

	for _, spec := range specs {
		base, err := resolveBase(spec.base)
		if err != nil {
			warn(err)
			continue
		}

		fsys, closeRoot, err := openTarget(base)
		if err != nil {
			warn(fmt.Errorf("agentaudit: opening global config base %q: %w", base, err))
			if !errors.Is(err, fs.ErrNotExist) {
				unreadable = true
			}
			continue
		}

		masked := maskFS{parent: fsys, allow: spec.allow}
		if !anyPresent(masked, spec.allow) {
			closeRoot()
			continue
		}

		rep, err := scanGlobal(masked, warn)
		closeRoot()
		if err != nil {
			return nil, false, err
		}
		blocks = append(blocks, block{Path: base, Report: rep})
	}
	return blocks, unreadable, nil
}

// anyPresent counts a non-ErrNotExist failure as present, so a permission
// fault degrades honestly instead of vanishing. It asks about the directory
// entry rather than what the entry resolves to: a symlink to a missing target
// is something the operator declared and can see, and resolving through it
// would drop the whole Base as absent.
func anyPresent(fsys fs.FS, allow map[string]bool) bool {
	for name := range allow {
		if _, err := fs.Lstat(fsys, name); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}
