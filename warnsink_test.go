package agentaudit

import (
	"context"
	"errors"
	"fmt"
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

// A sink nothing hears keeps no emission keys yet tallies what a sink
// something hears does, which keeps one key per distinct emission.
func TestWarnSinkWithoutEmitKeepsNoEmissionKeys(t *testing.T) {
	tests := []struct {
		name        string
		heard       bool
		wantEmitted int
	}{
		{"nothing hears it", false, 0},
		{"a WarnFunc hears it", true, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var emit func(error)
			calls := 0
			if tt.heard {
				emit = func(error) { calls++ }
			}
			sink := newWarnSink(emit)

			for _, file := range []string{"a/settings.json", "b/settings.json", "a/settings.json"} {
				err := &fs.PathError{Op: "openat", Path: file, Err: errors.New("permission denied")}
				sink.source(adapter.Warning{File: file, Err: err}, errors.New("wrapped: "+file))
			}
			sink.source(adapter.Warning{File: "a/settings.json", Err: &fs.PathError{Op: "statat", Path: "a/settings.json", Err: errors.New("permission denied")}}, errors.New("wrapped: stat"))
			sink.adapterFailure(adapter.AgentClaudeCode, errors.New("adapter aborted"), errors.New("wrapped: adapter aborted"))

			if got := len(sink.emitted); got != tt.wantEmitted {
				t.Fatalf("sink kept %d emission keys, want %d", got, tt.wantEmitted)
			}
			if calls != tt.wantEmitted {
				t.Fatalf("emit called %d times, want %d", calls, tt.wantEmitted)
			}
			if got := sink.unreadableSources(); got != 3 {
				t.Fatalf("unreadableSources() = %d, want 3 (two files and one adapter failure)", got)
			}
		})
	}
}

// Without a WarnFunc, liveSink builds a sink that keeps no emission keys;
// with one, a sink that keeps them.
func TestLiveSinkIsQuietWithoutAWarnFunc(t *testing.T) {
	if sink := New().liveSink(context.Background()); sink.emitted != nil {
		t.Fatal("a scan without a WarnFunc kept emission keys, want none")
	}
	if sink := New(WithWarnFunc(func(error) {})).liveSink(context.Background()); sink.emitted == nil {
		t.Fatal("a scan with a WarnFunc kept no emission keys, want them for its dedupe")
	}
}

// A sink nothing hears wants only the warnings it tallies; a sink something
// hears wants every warning.
func TestWarnSinkWantsOnlyWhatItTalliesOrEmits(t *testing.T) {
	missing := adapter.Warning{File: "a", Err: &fs.PathError{Op: "stat", Path: "a", Err: fs.ErrNotExist}}
	unreadable := adapter.Warning{File: "b", Err: &fs.PathError{Op: "open", Path: "b", Err: errors.New("permission denied")}}
	unparsed := adapter.Warning{File: "c", Err: errors.New("unexpected end of JSON input")}

	quiet := newWarnSink(nil)
	heard := newWarnSink(func(error) {})
	for _, tt := range []struct {
		name         string
		w            adapter.Warning
		quiet, heard bool
	}{
		{"missing", missing, false, true},
		{"unreadable", unreadable, true, true},
		{"unparsed", unparsed, true, true},
	} {
		if got := quiet.wants(tt.w); got != tt.quiet {
			t.Fatalf("quiet sink wants %s = %v, want %v", tt.name, got, tt.quiet)
		}
		if got := heard.wants(tt.w); got != tt.heard {
			t.Fatalf("heard sink wants %s = %v, want %v", tt.name, got, tt.heard)
		}
	}
}

type errorTextCounter struct{ calls *int }

func (e errorTextCounter) Error() string {
	*e.calls++
	return "simulated fault"
}

// A sink nothing hears renders no text for a source warning, neither its
// emission key nor its message, yet tallies it; a sink something hears
// renders both.
func TestWarnSinkWithoutEmitRendersNoWarningText(t *testing.T) {
	for _, heard := range []bool{false, true} {
		t.Run(fmt.Sprintf("heard=%v", heard), func(t *testing.T) {
			var emit func(error)
			if heard {
				emit = func(error) {}
			}
			sink := newWarnSink(emit)
			calls := 0
			sink.sourceFrom("agentaudit: discover", adapter.Warning{File: "a/settings.json", Err: errorTextCounter{&calls}})

			want := 0
			if heard {
				want = 2
			}
			if calls != want {
				t.Fatalf("error text read %d times, want %d (key and message when heard)", calls, want)
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
