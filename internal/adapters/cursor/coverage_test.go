package cursor

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// signatureProbe pairs a declared location with a document Parse has to
// surface an entity from, either from that location or from a file the
// document activates.
type signatureProbe struct {
	sig  adapter.Signature
	path string
	body string
	// beside is planted with the probe where the probe's own document
	// activates a file rather than declaring anything of its own: the entity
	// that file yields is what proves the document was read.
	beside map[string]string
	// located names the file the proving entity carries, defaulting to the
	// probe's own path.
	located string
}

func (p signatureProbe) plant() fstest.MapFS {
	fsys := fstest.MapFS{p.path: &fstest.MapFile{Data: []byte(p.body)}}
	for file, body := range p.beside {
		fsys[file] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func (p signatureProbe) locatedFile() string {
	if p.located != "" {
		return p.located
	}
	return p.path
}

var signatureProbes = []signatureProbe{
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "mcp.json"},
		path: ".cursor/mcp.json",
		body: `{"mcpServers":{"probe":{"command":"probe"}}}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "hooks.json"},
		path: ".cursor/hooks.json",
		body: `{"version":1,"hooks":{"sessionStart":[{"command":"probe"}]}}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "worktrees.json"},
		path: ".cursor/worktrees.json",
		body: `{"setup-worktree-unix":["probe"]}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "environment.json"},
		path: ".cursor/environment.json",
		body: `{"install":"probe"}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "sandbox.json"},
		path: ".cursor/sandbox.json",
		body: `{"type":"insecure_none"}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "cli.json"},
		path: ".cursor/cli.json",
		body: `{"permissions":{"allow":["Shell(probe)"]}}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor", File: "permissions.json"},
		path: ".cursor/permissions.json",
		body: `{"terminalAllowlist":["probe"]}`,
	},
	{
		sig:  adapter.Signature{Dir: ".cursor/hooks", Recursive: true},
		path: ".cursor/hooks/bootstrap.sh",
		body: "#!/bin/sh\n",
	},
	{
		sig:  adapter.Signature{Dir: ".cursor/skills", Recursive: true},
		path: ".cursor/skills/probe/SKILL.md",
		body: "---\nname: probe\n---\n",
	},
	{
		sig:  adapter.Signature{Dir: ".cursor/agents", Recursive: true},
		path: ".cursor/agents/probe.md",
		body: "---\nname: probe\n---\n",
	},
	{
		sig:  adapter.Signature{Dir: ".cursor-plugin", File: "plugin.json", AnyDepth: true},
		path: "plugins/ship-tool/.cursor-plugin/plugin.json",
		body: `{"hooks":{"sessionStart":[{"command":"probe"}]}}`,
	},
	{
		sig:     adapter.Signature{File: "plugin.json"},
		path:    "plugin.json",
		body:    `{"$schema":"https://agent-plugins.org/v1/plugin.json"}`,
		beside:  map[string]string{"mcp.json": `{"mcpServers":{"probe":{"command":"probe"}}}`},
		located: "mcp.json",
	},
}

// Every declared signature is reached by Parse from its probe's own planted
// file, which an entity must name as its Location.File, or, where the planted
// document activates a file beside it, that file must.
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
			entities, _, err := New().Parse(p.plant())
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			located := p.locatedFile()
			if !slices.ContainsFunc(entities, func(e ir.Entity) bool {
				return ir.LocationOf(e).File == located
			}) {
				t.Fatalf("Parse() surfaced no entity located in %q, so nothing proves Parse reached %q", located, p.path)
			}
		})
	}

	for _, p := range signatureProbes {
		if !declared[p.sig] {
			t.Errorf("signatureProbes pins %+v, which Signatures() no longer declares", p.sig)
		}
	}
}
