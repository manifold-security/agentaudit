package agentaudit

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// ScanGlobal returns a Report for fsys: it does not resolve a path or name a
// home.
func (s *Scanner) ScanGlobal(fsys fs.FS) (finding.Report, error) {
	return s.scanFS(bound(context.Background(), fsys, s.maxFileSize), newWarnSink(s.emitFunc()), globalPass{})
}

type globalPass struct{}

func (globalPass) activates(a adapter.Adapter, fsys fs.FS, matched bool) bool {
	if matched {
		return true
	}
	gs, ok := a.(adapter.GlobalScoped)
	return ok && anyEntryPresent(fsys, gs.GlobalConfig().Entries)
}

// entities never lets a ParseGlobal fault discard Parse's own entities:
// ParseGlobal can surface keys Parse does not, so a fault in it degrades
// only its own contribution, folded into warnings rather than returned as
// a trailing error scanFS would otherwise use to discard everything this
// call found.
func (globalPass) entities(a adapter.Adapter, fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	entities, warnings, err := a.Parse(fsys)
	if err != nil {
		return nil, warnings, err
	}
	gs, ok := a.(adapter.GlobalScoped)
	if !ok {
		return entities, warnings, nil
	}
	global, globalWarnings, globalErr := gs.ParseGlobal(fsys)
	warnings = append(warnings, globalWarnings...)
	if globalErr != nil {
		warnings = append(warnings, adapter.Warning{
			File: strings.Join(gs.GlobalConfig().Entries, ","),
			Err:  adapter.Unreadable(globalErr),
		})
		return entities, warnings, nil
	}
	return append(entities, global...), warnings, nil
}

// anyEntryPresent mirrors cmd/agentaudit's anyPresent in shape, deliberately
// not shared. See anyPresent's own doc for the presence rule both apply.
func anyEntryPresent(fsys fs.FS, entries []string) bool {
	for _, name := range entries {
		if _, err := fs.Stat(fsys, name); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}
