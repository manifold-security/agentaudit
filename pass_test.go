package agentaudit

import (
	"testing"
	"testing/fstest"
)

func TestProjectPass_ActivatesOnlyOnSignatureMatch(t *testing.T) {
	p := projectPass{}
	if !p.activates(nil, fstest.MapFS{}, true) {
		t.Fatalf("activates(matched=true) = false, want true")
	}
	if p.activates(nil, fstest.MapFS{}, false) {
		t.Fatalf("activates(matched=false) = true, want false")
	}
}
