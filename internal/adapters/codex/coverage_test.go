package codex

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

type signatureProbe struct {
	sig    adapter.Signature
	path   string
	body   string
	beside map[string]string
}

var signatureProbes = []signatureProbe{
	{
		sig:  adapter.Signature{Dir: ".codex", File: "config.toml"},
		path: configFileName,
		body: "sandbox_mode = \"danger-full-access\"\n",
	},
	{
		sig:  adapter.Signature{Dir: ".codex", File: "hooks.json"},
		path: hooksFileName,
		body: `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./ok.sh"}]}]}}`,
	},
	{
		sig:    adapter.Signature{Dir: ".agents/skills", Recursive: true},
		path:   ".agents/skills/probe/scripts/probe.sh",
		body:   "#!/bin/sh\n",
		beside: map[string]string{".agents/skills/probe/SKILL.md": "---\nname: probe\n---\n"},
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
			planted := []string{p.path}
			for name := range p.beside {
				planted = append(planted, name)
			}
			for _, name := range planted {
				if !adapter.Matches(name, []adapter.Signature{s}) {
					t.Fatalf("planted path %q does not match its own signature %+v", name, s)
				}
				for j, other := range sigs {
					if j != i && adapter.Matches(name, []adapter.Signature{other}) {
						t.Fatalf("planted path %q also matches signature %+v", name, other)
					}
				}
			}
			fsys := fstest.MapFS{p.path: &fstest.MapFile{Data: []byte(p.body)}}
			for name, body := range p.beside {
				fsys[name] = &fstest.MapFile{Data: []byte(body)}
			}

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
