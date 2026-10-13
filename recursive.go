package agentaudit

import (
	"fmt"
	"io/fs"
	"slices"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/discovery"
)

// ProjectReport is one project's report; Path "." is the container itself.
type ProjectReport struct {
	Path   string
	Report finding.Report
}

// ScanRecursive scans the projects beneath fsys. A call that returns no error
// returns at least one entry, so no empty result renders as a clean scan.
func (s *Scanner) ScanRecursive(fsys fs.FS) ([]ProjectReport, error) {
	emit := s.emitFunc()
	containerSink := newWarnSink(emit)

	roots, err := s.enumerate(fsys, containerSink)
	if err != nil {
		return nil, err
	}

	// A directory the enumeration could not read blinds it; a parse failure
	// does not — that source was reached, so its project was enumerated.
	enumerationBlinded := containerSink.unreadableSources() > 0
	noProjectFound := len(roots) == 0
	containerIsProject := slices.Contains(roots, ".")

	var out []ProjectReport
	if enumerationBlinded || noProjectFound || containerIsProject {
		rep, err := s.scanFS(fsys, containerSink, projectPass{})
		if err != nil {
			return nil, err
		}
		out = append(out, ProjectReport{Path: ".", Report: rep})
	}
	for _, root := range roots {
		if root == "." {
			continue
		}
		sub, err := subtree(fsys, root)
		if err != nil {
			return nil, err
		}
		rep, err := s.scanFS(sub, newWarnSink(emit), projectPass{})
		if err != nil {
			return nil, err
		}
		out = append(out, ProjectReport{Path: root, Report: rep})
	}
	return out, nil
}

// enumerate lists project roots, sharing sink with the container's own
// scan so a fault reached by both counts once.
func (s *Scanner) enumerate(fsys fs.FS, sink *warnSink) ([]string, error) {
	roots, warnings, err := discovery.Projects(fsys, s.selectedAdapters())
	for _, w := range warnings {
		sink.source(w, fmt.Errorf("agentaudit: enumerate: %s: %w", w.File, w.Err))
	}
	if err != nil {
		return nil, fmt.Errorf("agentaudit: enumerate: %w", err)
	}
	return roots, nil
}
