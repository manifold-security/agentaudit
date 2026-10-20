package main

import "testing"

func TestBinaryE2E_RefusesAURLOutsideTheGrammar(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, tc := range refusedURLs {
		t.Run(tc.arg, func(t *testing.T) {
			stdout, stderr, code := runBinary(t, bin, t.TempDir(), tc.arg)
			if code != 2 {
				t.Errorf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if want := refusalLine(tc.arg, tc.reason, tc.redacted); stderr != want {
				t.Errorf("stderr = %q, want exactly %q", stderr, want)
			}
		})
	}
}
