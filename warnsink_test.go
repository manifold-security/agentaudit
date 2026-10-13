package agentaudit

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
)

func TestWarnSinkAdapterFailureEmitsAndCountsOnce(t *testing.T) {
	var emitted []error
	sink := newWarnSink(func(err error) { emitted = append(emitted, err) })

	failure := errors.New("adapter aborted")
	sink.adapterFailure(adapter.AgentClaudeCode, failure, errors.New("wrapped: adapter aborted"))
	sink.adapterFailure(adapter.AgentClaudeCode, failure, errors.New("wrapped: adapter aborted"))

	if len(emitted) != 1 {
		t.Fatalf("emit called %d times, want exactly 1 (repeat identical failure must dedupe)", len(emitted))
	}
	if got := sink.unreadableSources(); got != 1 {
		t.Fatalf("unreadableSources() = %d, want 1", got)
	}
}

func TestWarnSinkAdapterFailureCountsDistinctFailures(t *testing.T) {
	var emitted []error
	sink := newWarnSink(func(err error) { emitted = append(emitted, err) })

	sink.adapterFailure(adapter.AgentClaudeCode, errors.New("first failure"), errors.New("wrapped: first"))
	sink.adapterFailure(adapter.AgentClaudeCode, errors.New("second failure"), errors.New("wrapped: second"))

	if len(emitted) != 2 {
		t.Fatalf("emit called %d times, want 2", len(emitted))
	}
	if got := sink.unreadableSources(); got != 2 {
		t.Fatalf("unreadableSources() = %d, want 2", got)
	}
}

// The sink's split keys in action: one path both layers trip over reaches
// the callback twice and the tally once.
func TestWarnSinkSourceEmitsBothLayersAndCountsTheFileOnce(t *testing.T) {
	var emitted []error
	sink := newWarnSink(func(err error) { emitted = append(emitted, err) })

	const file = ".claude/settings.json"
	statErr := &fs.PathError{Op: "statat", Path: file, Err: errors.New("path escapes from parent")}
	openErr := &fs.PathError{Op: "openat", Path: file, Err: errors.New("path escapes from parent")}

	sink.source(adapter.Warning{File: file, Err: statErr}, errors.New("discover: statat"))
	sink.source(adapter.Warning{File: file, Err: openErr}, errors.New("parse claude-code: openat"))

	if len(emitted) != 2 {
		t.Fatalf("emit called %d times, want 2 (each layer's diagnostic must still reach stderr)", len(emitted))
	}
	if got := sink.unreadableSources(); got != 1 {
		t.Fatalf("unreadableSources() = %d, want 1 (one file is one unreadable source)", got)
	}
}

func TestWarnSinkSourceCountsDistinctUnreadableFilesSeparately(t *testing.T) {
	var emitted []error
	sink := newWarnSink(func(err error) { emitted = append(emitted, err) })

	first := &fs.PathError{Op: "openat", Path: "a/settings.json", Err: errors.New("permission denied")}
	second := &fs.PathError{Op: "openat", Path: "b/settings.json", Err: errors.New("permission denied")}

	sink.source(adapter.Warning{File: "a/settings.json", Err: first}, errors.New("wrapped: a"))
	sink.source(adapter.Warning{File: "b/settings.json", Err: second}, errors.New("wrapped: b"))

	if len(emitted) != 2 {
		t.Fatalf("emit called %d times, want 2", len(emitted))
	}
	if got := sink.unreadableSources(); got != 2 {
		t.Fatalf("unreadableSources() = %d, want 2 (distinct files must not merge)", got)
	}
}

// The two tallies dedupe in separate namespaces, so neither loses a fault
// to the other's dedupe — including when both faults name one path.
func TestWarnSinkSourceCountsUnreadableAndUnparsedIndependently(t *testing.T) {
	tests := []struct {
		name                 string
		unreadable, unparsed string
	}{
		{"distinct files", "a/settings.json", "b/agent.md"},
		{"one file in both buckets", "shared.json", "shared.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var emitted []error
			sink := newWarnSink(func(err error) { emitted = append(emitted, err) })

			readErr := &fs.PathError{Op: "openat", Path: tt.unreadable, Err: errors.New("permission denied")}
			sink.source(adapter.Warning{File: tt.unreadable, Err: readErr}, errors.New("wrapped: read"))
			sink.source(adapter.Warning{File: tt.unparsed, Err: errors.New("yaml: mapping values are not allowed")}, errors.New("wrapped: parse"))

			if len(emitted) != 2 {
				t.Fatalf("emit called %d times, want 2", len(emitted))
			}
			if got := sink.unreadableSources(); got != 1 {
				t.Fatalf("unreadableSources() = %d, want 1", got)
			}
			if got := sink.unparsedSources(); got != 1 {
				t.Fatalf("unparsedSources() = %d, want 1", got)
			}
		})
	}
}

func TestWarnSinkSourceCountsOnlyGenuineReadFailures(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantUnreadable int
		wantUnparsed   int
	}{
		{"permission denied is unreadable", &fs.PathError{Op: "open", Path: "a", Err: errors.New("permission denied")}, 1, 0},
		{"not exist is neither", &fs.PathError{Op: "open", Path: "b", Err: fs.ErrNotExist}, 0, 0},
		{"malformed json is unparsed", errors.New("unexpected end of JSON input"), 0, 1},
		{"scanner refusal is unreadable", adapter.Unreadable(errors.New("refusing to read \"x\": not a regular file")), 1, 0},
		{"symlink loop refusal is unreadable", adapter.Unreadable(errors.New("refusing to walk \"y\": not a real directory")), 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var emitted int
			sink := newWarnSink(func(error) { emitted++ })
			sink.source(adapter.Warning{File: tt.name, Err: tt.err}, errors.New("wrapped"))
			if emitted != 1 {
				t.Fatalf("emit called %d times, want 1 (every distinct warning must still emit)", emitted)
			}
			if got := sink.unreadableSources(); got != tt.wantUnreadable {
				t.Fatalf("unreadableSources() = %d, want %d", got, tt.wantUnreadable)
			}
			if got := sink.unparsedSources(); got != tt.wantUnparsed {
				t.Fatalf("unparsedSources() = %d, want %d", got, tt.wantUnparsed)
			}
		})
	}
}
