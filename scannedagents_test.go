package agentaudit

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
)

// A recognized agent that declares nothing is distinguishable from a config
// no adapter knows, which is the pair the report otherwise renders
// identically.
func TestScan_ScannedAgentsSeparatesARecognizedSilentConfigFromAnUnknownOne(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
		want []string
	}{
		{
			name: "a recognized agent declaring nothing",
			fsys: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(`{}`)}},
			want: []string{"claude-code"},
		},
		{
			name: "a config no adapter knows",
			fsys: fstest.MapFS{".config/someagent/config.json": &fstest.MapFile{
				Data: []byte(`{"mcpServers":{"fetch":{"command":"curl"}}}`),
			}},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := New().Scan(tt.fsys)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			if rep.HasFindings() {
				t.Fatalf("Scan() = %+v, want no finding: a difference in findings would make the comparison about something else", rep.Findings())
			}
			if got := rep.ScannedAgents(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ScannedAgents() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// An adapter whose Parse failed stays in the scanned set. It was scanned and
// its blind spot is already carried by the degradation tally, so dropping it
// would shrink the list under an I/O fault into a claim that no known agent
// config is here.
func TestScan_ScannedAgentsKeepsAnAdapterWhoseParseFailed(t *testing.T) {
	a := stubFailingParseAdapter{stubGlobalScopedAdapter{
		agent: adapter.AgentClaudeCode,
		sigs:  []adapter.Signature{{Dir: ".claude", File: "settings.json"}},
	}}
	fsys := fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(`{}`)}}

	rep, err := New(WithAdapters(a), WithWarnFunc(func(error) {})).Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if rep.UnreadableSources() == 0 {
		t.Fatalf("premise invalid: the Parse fault never reached the degradation tally")
	}
	if got, want := rep.ScannedAgents(), []string{"claude-code"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ScannedAgents() = %+v, want %+v", got, want)
	}
}

// WithAgents narrows the scanned set to the agents the caller asked for, so
// the list never claims an agent the scan was told to skip.
func TestScan_ScannedAgentsHonoursWithAgents(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{}`)},
		".cursor/mcp.json":      &fstest.MapFile{Data: []byte(`{}`)},
	}

	tests := []struct {
		name    string
		options []Option
		want    []string
	}{
		{"every registered adapter", nil, []string{"claude-code", "cursor"}},
		{"one agent selected", []Option{WithAgents(AgentCursor)}, []string{"cursor"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := New(tt.options...).Scan(fsys)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			if got := rep.ScannedAgents(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ScannedAgents() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A global scan names an adapter its declared home entry activated, which a
// discovery source alone would miss: the same tree carries no source for
// this adapter's signature, so a project scan of it names nobody.
func TestScanGlobal_ScannedAgentsNamesAnAdapterNoDiscoverySourceMatched(t *testing.T) {
	a := stubGlobalScopedAdapter{
		agent:   adapter.AgentClaudeCode,
		sigs:    []adapter.Signature{{Dir: ".claude", File: "settings.json"}},
		entries: []string{".claude"},
	}
	fsys := fstest.MapFS{".claude/unmatched.txt": &fstest.MapFile{Data: []byte("x")}}

	global, err := New(WithAdapters(a)).ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if got, want := global.ScannedAgents(), []string{"claude-code"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanGlobal().ScannedAgents() = %+v, want %+v", got, want)
	}

	project, err := New(WithAdapters(a)).Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := project.ScannedAgents(); len(got) != 0 {
		t.Fatalf("Scan().ScannedAgents() = %+v, want empty: no signature matched this tree", got)
	}
}

// Each project carries its own scanned set: two siblings configured for
// different agents name different agents, which one set shared across the
// walk could not produce.
func TestScanRecursive_ScannedAgentsIsPerProject(t *testing.T) {
	fsys := fstest.MapFS{
		"claudeproj/.claude/settings.json": &fstest.MapFile{Data: []byte(`{}`)},
		"cursorproj/.cursor/mcp.json":      &fstest.MapFile{Data: []byte(`{}`)},
	}

	reports, err := New().ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}

	got := make(map[string][]string, len(reports))
	for _, pr := range reports {
		got[pr.Path] = pr.Report.ScannedAgents()
	}
	want := map[string][]string{
		"claudeproj": {"claude-code"},
		"cursorproj": {"cursor"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("per-project ScannedAgents() = %+v, want %+v", got, want)
	}
}
