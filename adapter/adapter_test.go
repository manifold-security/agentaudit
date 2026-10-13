package adapter

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

type stubAdapter struct{}

func (stubAdapter) Agent() AgentID { return AgentClaudeCode }

func (stubAdapter) Signatures() []Signature {
	return []Signature{
		{File: ".mcp.json"},
		{Dir: ".claude", Recursive: true},
	}
}

func (stubAdapter) Parse(fsys fs.FS) ([]ir.Entity, []Warning, error) { return nil, nil, nil }

var _ Adapter = stubAdapter{}

func TestAgentSurfacesClaudeCode(t *testing.T) {
	got := stubAdapter{}.Agent()
	if got != AgentClaudeCode {
		t.Fatalf("Agent() = %q, want %q", got, AgentClaudeCode)
	}
	if string(got) != "claude-code" {
		t.Fatalf("Agent() literal = %q, want %q", string(got), "claude-code")
	}
}

// A wrapped Warning classifies as ErrUnreadable without masking the cause
// or the message the facade prints; an unwrapped one does not classify.
func TestUnreadableClassifiesWithoutMaskingTheCause(t *testing.T) {
	cause := errors.New("boom")
	w := Warning{File: ".claude/settings.json", Err: Unreadable(cause)}

	if !errors.Is(w.Err, ErrUnreadable) {
		t.Fatalf("errors.Is(%v, ErrUnreadable) = false, want true", w.Err)
	}
	if !errors.Is(w.Err, cause) {
		t.Fatalf("errors.Is(%v, cause) = false, want the cause reachable", w.Err)
	}
	if got := w.Err.Error(); got != cause.Error() {
		t.Fatalf("Error() = %q, want the cause's own text %q", got, cause.Error())
	}
	if errors.Is(cause, ErrUnreadable) {
		t.Fatalf("errors.Is(cause, ErrUnreadable) = true, want an unwrapped error not to classify")
	}
}
