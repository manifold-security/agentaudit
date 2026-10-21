package adapter

import (
	"errors"
	"io/fs"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// AgentID identifies a supported agent: the frozen token that rule JSON
// (appliesTo) and facade filtering (WithAgents) match on.
type AgentID string

// AgentClaudeCode is the frozen id for the Claude Code adapter.
const AgentClaudeCode AgentID = "claude-code"

// AgentCursor is the frozen id for the Cursor adapter.
const AgentCursor AgentID = "cursor"

// AgentCodex is the frozen id for the Codex adapter.
const AgentCodex AgentID = "codex"

// Warning reports one source the scan did not fully use. The scan continues
// with the rest.
type Warning struct {
	File string
	Err  error
}

// ErrUnreadable marks a Warning as a scanner refusal rather than an I/O
// failure or a parse fault on a file the scanner did read.
var ErrUnreadable = errors.New("adapter: refused to read an existing source")

// Unreadable wraps err so errors.Is reports ErrUnreadable, leaving err's
// Error() text and Unwrap chain intact.
func Unreadable(err error) error { return unreadable{err} }

type unreadable struct{ error }

func (u unreadable) Unwrap() error        { return u.error }
func (u unreadable) Is(target error) bool { return target == ErrUnreadable }

// Adapter is the public port every agent adapter implements.
type Adapter interface {
	Agent() AgentID
	// Signatures returns the declarative fs.FS locations this adapter owns.
	Signatures() []Signature
	// Parse reads fsys at this adapter's Signatures. A malformed source is
	// reported as a Warning so every other source still parses; an error
	// means an fs.FS failure that stopped Parse entirely.
	Parse(fsys fs.FS) ([]ir.Entity, []Warning, error)
}
