package registry

import (
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/adapters/codex"
	"github.com/manifold-security/agentaudit/internal/adapters/cursor"
)

// The wired set is exhaustive in both directions: an adapter dropped from
// agents.go stops being scanned silently, and a stub wired in its place would
// report nothing while every id-level check still passed.
func TestAdaptersReturnsEveryWiredAgentAdapter(t *testing.T) {
	wantTypes := map[adapter.AgentID]any{
		adapter.AgentClaudeCode: claude.Adapter{},
		adapter.AgentCursor:     cursor.Adapter{},
		adapter.AgentCodex:      codex.Adapter{},
	}

	adapters := Adapters()
	if len(adapters) != len(wantTypes) {
		t.Fatalf("Adapters() len = %d, want %d", len(adapters), len(wantTypes))
	}
	for _, a := range adapters {
		want, ok := wantTypes[a.Agent()]
		if !ok {
			t.Fatalf("Adapters() wired an unexpected agent %q (%T)", a.Agent(), a)
		}
		if reflect.TypeOf(a) != reflect.TypeOf(want) {
			t.Errorf("agent %q type = %T, want %T", a.Agent(), a, want)
		}
		delete(wantTypes, a.Agent())
	}
	if len(wantTypes) != 0 {
		t.Errorf("Adapters() wired no adapter for: %v", wantTypes)
	}
}

// Two adapters claiming one id would make appliesTo and WithAgents ambiguous,
// and the second would silently shadow the first in any id-keyed map.
func TestAdaptersClaimDistinctAgentIDs(t *testing.T) {
	seen := map[adapter.AgentID]bool{}
	for _, a := range Adapters() {
		if seen[a.Agent()] {
			t.Errorf("agent id %q is claimed by more than one adapter", a.Agent())
		}
		seen[a.Agent()] = true
	}
}

// Registration must stay explicit and greppable in agents.go, never
// contributed via func init().
func TestNoInitFunctionInAgents(t *testing.T) {
	data, err := os.ReadFile("agents.go")
	if err != nil {
		t.Fatalf("read agents.go: %v", err)
	}
	if strings.Contains(string(data), "func init(") {
		t.Fatalf("agents.go must not define func init(); registration must be explicit")
	}
}

// anchoredReaches reports whether an anchored signature can match a path at
// or below entry: the signature's own location sits inside the entry, or a
// recursive signature's subtree contains it. A depth-agnostic signature is
// excluded here on purpose — it matches beneath any prefix at all, so
// counting it first would let it vouch for every entry and leave the
// behavioral half of the guard below unreached.
func anchoredReaches(sigs []adapter.Signature, entry string) bool {
	for _, s := range sigs {
		if s.AnyDepth {
			continue
		}
		loc := path.Join(s.Dir, s.File)
		if loc == entry || strings.HasPrefix(loc, entry+"/") {
			return true
		}
		if s.Recursive && strings.HasPrefix(entry, loc+"/") {
			return true
		}
	}
	return false
}

// depthAgnosticPrefixes lists the declared global prefixes justified by a
// depth-agnostic signature alone. Such a signature matches at any depth, so
// it would vouch for every prefix alike and can settle nothing; each entry
// here is instead a judgement about where the agent installs plugins, with
// cmd/agentaudit's TestGlobalConfig_ReachesEveryClaudeSignatureLoadPath and
// TestGlobalConfig_ReachesEveryCursorSignatureLoadPath each proving their own
// agent's entry is reached.
var depthAgnosticPrefixes = map[adapter.AgentID]map[string]bool{
	adapter.AgentClaudeCode: {".claude/plugins": true},
	adapter.AgentCursor:     {".cursor/plugins/local": true},
}

// An admitted global prefix nothing can ever match is the defect here: an
// anchored Signatures() entry lies within it, or ParseGlobal provably reads
// it. The second half is behavioral, never a name check — the prefix is
// planted as a file whose bytes parse as no known format, and ParseGlobal must
// return a Warning naming it, so a silent (nil, nil, nil) fails rather than
// passes.
func TestGlobalScopedAdaptersDeclareNoInertGlobalSignature(t *testing.T) {
	probed := 0
	for _, a := range Adapters() {
		gs, ok := a.(adapter.GlobalScoped)
		if !ok {
			continue
		}

		for _, entry := range gs.GlobalConfig().Entries {
			if depthAgnosticPrefixes[a.Agent()][entry] {
				continue
			}
			if anchoredReaches(a.Signatures(), entry) {
				continue
			}

			probed++
			fsys := fstest.MapFS{entry: &fstest.MapFile{Data: []byte("\x00not valid in any accepted format")}}
			_, warnings, err := gs.ParseGlobal(fsys)
			if err != nil {
				t.Errorf("%s.ParseGlobal() error = %v, want nil (a malformed source degrades to a Warning)", a.Agent(), err)
				continue
			}
			named := false
			for _, w := range warnings {
				if w.File == entry {
					named = true
				}
			}
			if !named {
				t.Errorf("%s declares global config entry %q that no anchored signature lies within, and ParseGlobal(fsys) over a malformed %q produced no Warning naming it: warnings=%v; an admitted entry nothing can ever match is exactly the defect this guard exists to catch", a.Agent(), entry, entry, warnings)
			}
		}
	}

	if probed == 0 {
		t.Fatal("no declared entry reached the behavioral arm, so this guard asserted nothing")
	}
}
