package claude

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// signatureProbe pairs a declared location with a document a parser for that
// location has to surface an entity from.
type signatureProbe struct {
	sig  adapter.Signature
	path string
	body string
}

var signatureProbes = []signatureProbe{
	{
		sig:  adapter.Signature{Dir: ".claude", File: "settings.json", Recursive: false},
		path: ".claude/settings.json",
		body: `{"apiKeyHelper":"probe"}`,
	},
	{
		sig:  adapter.Signature{Dir: ".claude", File: "settings.local.json", Recursive: false},
		path: ".claude/settings.local.json",
		body: `{"apiKeyHelper":"probe"}`,
	},
	{
		sig:  adapter.Signature{Dir: ".", File: ".mcp.json", Recursive: false},
		path: ".mcp.json",
		body: `{"mcpServers":{"probe":{"command":"probe"}}}`,
	},
	{
		sig:  adapter.Signature{Dir: ".claude/agents", Recursive: true},
		path: ".claude/agents/probe.md",
		body: "---\nname: probe\n---\n",
	},
	{
		sig:  adapter.Signature{Dir: ".claude/skills", Recursive: true},
		path: ".claude/skills/probe/SKILL.md",
		body: "---\nname: probe\n---\n",
	},
	{
		sig:  adapter.Signature{Dir: ".claude/commands", Recursive: true},
		path: ".claude/commands/probe.md",
		body: "Run !`echo probe` to deploy.\n",
	},
	{
		sig:  adapter.Signature{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true},
		path: ".claude-plugin/plugin.json",
		body: `{"name":"probe"}`,
	},
}

// Every declared signature is reached by Parse from its probe's own planted
// file, which some entity must name as its Location.File. Cross-checked both
// ways, so a stranded probe fails as loudly as a signature Parse never reaches.
func TestParseReachesEveryDeclaredSignature(t *testing.T) {
	probes := map[adapter.Signature]signatureProbe{}
	for _, p := range signatureProbes {
		if _, dup := probes[p.sig]; dup {
			t.Fatalf("signatureProbes lists %+v twice", p.sig)
		}
		probes[p.sig] = p
	}

	declared := map[adapter.Signature]bool{}
	sigs := New().Signatures()
	for i, s := range sigs {
		declared[s] = true
		p, ok := probes[s]
		if !ok {
			t.Errorf("Signatures() declares %+v with no probe in signatureProbes, so nothing proves Parse reads it", s)
			continue
		}
		t.Run(p.path, func(t *testing.T) {
			if !adapter.Matches(p.path, []adapter.Signature{s}) {
				t.Fatalf("probe path %q does not match its own signature %+v", p.path, s)
			}
			for j, other := range sigs {
				if j != i && adapter.Matches(p.path, []adapter.Signature{other}) {
					t.Fatalf("probe path %q also matches signature %+v", p.path, other)
				}
			}
			fsys := fstest.MapFS{p.path: &fstest.MapFile{Data: []byte(p.body)}}

			entities, _, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if !slices.ContainsFunc(entities, func(e ir.Entity) bool {
				return ir.LocationOf(e).File == p.path
			}) {
				t.Fatalf("Parse() surfaced no entity located in %q, so nothing proves Parse reached the planted file", p.path)
			}
		})
	}

	for _, p := range signatureProbes {
		if !declared[p.sig] {
			t.Errorf("signatureProbes pins %+v, which Signatures() no longer declares", p.sig)
		}
	}
}
