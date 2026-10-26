package agentaudit

import (
	"context"

	"github.com/manifold-security/agentaudit/treefs"
)

// Select runs Scan, or ScanRecursive under WithRecursive, over t with
// warnings suppressed, and returns, sorted, the paths of unheld blobs it read.
func (s *Scanner) Select(t *treefs.FS) ([]string, error) {
	return s.SelectContext(context.Background(), t)
}

// SelectContext is Select bounded by ctx: once ctx is done it fails with
// ctx.Err().
func (s *Scanner) SelectContext(ctx context.Context, t *treefs.FS) ([]string, error) {
	quiet := *s
	quiet.warn = nil
	// Drop earlier reads: SelectContext returns only its own scan's.
	t.Missing()
	var err error
	if s.recursive {
		_, err = quiet.scanRecursive(ctx, t)
	} else {
		_, err = quiet.ScanContext(ctx, t)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}
	return t.Missing(), nil
}
