package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	jsonreport "github.com/manifold-security/agentaudit/internal/report/json"
	mdreport "github.com/manifold-security/agentaudit/internal/report/md"
)

const (
	jsonReportFilename = "agentaudit-report.json"
	mdReportFilename   = "agentaudit-report.md"
)

// createFile refuses a non-regular file at name: the default target is the
// current directory, which a scanned repository controls.
var createFile = func(name string) (io.WriteCloser, error) {
	info, err := os.Lstat(name)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return nil, errors.New("exists and is not a regular file, refusing to write through it")
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return os.Create(name) //nolint:gosec // G304: a fixed report name
}

func jsonEntries(blocks []block) []jsonreport.Entry {
	entries := make([]jsonreport.Entry, len(blocks))
	for i, b := range blocks {
		entries[i] = jsonreport.Entry{Report: b.Report, Meta: jsonreport.Meta{Path: b.Path}}
	}
	return entries
}

// writeReportFiles writes json before md, so a failure on the second still
// leaves the first on disk.
func writeReportFiles(target string, blocks []block, emptyLine string) error {
	if target == "json" || target == "all" {
		if err := writeReportFile(jsonReportFilename, func(w io.Writer) error {
			return jsonreport.Write(w, jsonEntries(blocks))
		}); err != nil {
			return err
		}
	}
	if target == "md" || target == "all" {
		if err := writeReportFile(mdReportFilename, func(w io.Writer) error {
			if emptyLine != "" {
				_, err := fmt.Fprintln(w, emptyLine)
				return err
			}
			for _, b := range blocks {
				if err := mdreport.Write(w, b.Report, mdreport.Meta{Path: b.Path}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// writeReportFile treats a Close failure as a real failure: an unflushed
// write loses content just as surely as a render error does.
func writeReportFile(name string, render func(io.Writer) error) error {
	f, err := createFile(name)
	if err != nil {
		return fmt.Errorf("agentaudit: creating %s: %w", name, err)
	}
	var renderErr, closeErr error
	if err := render(f); err != nil {
		renderErr = fmt.Errorf("agentaudit: writing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		closeErr = fmt.Errorf("agentaudit: closing %s: %w", name, err)
	}
	return errors.Join(renderErr, closeErr)
}
