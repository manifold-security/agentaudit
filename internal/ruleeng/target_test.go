package ruleeng

import (
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// knownTargetCases is the hand-written enumeration
// TestTargetsRegistryCoversAllKinds cross-checks the registry against.
var knownTargetCases = []struct {
	target string
	want   bool
}{
	{ir.KindHook, true},
	{ir.KindMCPServer, true},
	{ir.KindEnvVar, true},
	{ir.KindSubagent, true},
	{ir.KindSkill, true},
	{ir.KindPlugin, true},
	{ir.KindSandbox, true},
	{ir.KindStatusLine, true},
	{ir.KindCredentialHelper, true},
	{ir.KindPermissionMode, true},
	{ir.KindMCPApproval, true},
	{ir.KindBundledPayload, true},
	{ir.KindInlineShell, true},
	{ir.KindPluginExecutable, true},
	{ir.KindProvisioner, true},
	{ir.KindNetworkPolicy, true},
	{ir.KindToolPermission, true},
	{ir.KindInstructionText, true},
	{ir.KindLSPServer, true},
	{"not-a-real-kind", false},
}

func TestKnownTarget(t *testing.T) {
	for _, tt := range knownTargetCases {
		t.Run(tt.target, func(t *testing.T) {
			if got := knownTarget(tt.target); got != tt.want {
				t.Fatalf("knownTarget(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestNewEntity(t *testing.T) {
	entity, ok := newEntity(ir.KindMCPServer)
	if !ok {
		t.Fatalf("newEntity(%q) ok = false, want true", ir.KindMCPServer)
	}
	if entity.Kind() != ir.KindMCPServer {
		t.Fatalf("newEntity(%q).Kind() = %q", ir.KindMCPServer, entity.Kind())
	}

	if _, ok := newEntity("not-a-real-kind"); ok {
		t.Fatalf("newEntity(unknown) ok = true, want false")
	}
}

// A rule resolves its target through this registry, so a kind registered
// with no row here is reachable by a rule no test names, and a row naming a
// kind the registry dropped stops resolving without anything going red.
func TestTargetsRegistryCoversAllKinds(t *testing.T) {
	enumerated := map[string]bool{}
	for _, tt := range knownTargetCases {
		if tt.want {
			enumerated[tt.target] = true
		}
	}

	for target := range targets {
		if !enumerated[target] {
			t.Errorf("targets registers %q with no row in knownTargetCases", target)
		}
	}
	for target := range enumerated {
		if _, ok := targets[target]; !ok {
			t.Errorf("knownTargetCases names %q, which targets no longer registers", target)
		}
	}
}
