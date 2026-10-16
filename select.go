package agentaudit

import "github.com/manifold-security/agentaudit/treefs"

// Select runs Scan, or ScanRecursive under WithRecursive, over t with
// warnings suppressed, and returns, sorted, the paths of unheld blobs it read.
func (s *Scanner) Select(t *treefs.FS) ([]string, error) {
	quiet := *s
	quiet.warn = nil
	// Drop earlier reads: Select returns only its own scan's.
	t.Missing()
	var err error
	if s.recursive {
		_, err = quiet.ScanRecursive(t)
	} else {
		_, err = quiet.Scan(t)
	}
	if err != nil {
		return nil, err
	}
	return t.Missing(), nil
}
