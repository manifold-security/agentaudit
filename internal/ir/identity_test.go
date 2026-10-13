package ir

import "testing"

func TestIdentityHelper(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		fields []string
		want   string
	}{
		{"two fields", "k", []string{"a", "b"}, "k\x1fa\x1fb"},
		{"single field", "hook", []string{"only"}, "hook\x1fonly"},
		{"no fields", "skill", nil, "skill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identity(tt.kind, tt.fields...)
			if got != tt.want {
				t.Fatalf("identity(%q, %v) = %q, want %q", tt.kind, tt.fields, got, tt.want)
			}
		})
	}
}

// Location is pure provenance and never reaches Identity(), so two entities
// of one kind with identical key fields but different Location mint the same
// id.
func TestIdentityStableAcrossLocation(t *testing.T) {
	h1 := Hook{Event: "PreToolUse", Matcher: "Bash", Command: "echo hi", Location: Location{File: "a.json", Key: "hooks[0]"}}
	h2 := Hook{Event: "PreToolUse", Matcher: "Bash", Command: "echo hi", Location: Location{File: "b.json", Key: "hooks[3]"}}
	if h1.Identity() != h2.Identity() {
		t.Fatalf("Identity() differs across Location: %q vs %q", h1.Identity(), h2.Identity())
	}

	p1 := Plugin{Name: "git-helper", Version: "1.0.0", Location: Location{File: "plugins.json", Key: "plugins[0]"}}
	p2 := Plugin{Name: "git-helper", Version: "2.0.0", Location: Location{File: "other.json", Key: "plugins[1]"}}
	if p1.Identity() != p2.Identity() {
		t.Fatalf("Plugin Identity() differs across Location/Version: %q vs %q", p1.Identity(), p2.Identity())
	}
}

func TestIdentityUniquenessPerKeyField(t *testing.T) {
	tests := []struct {
		name     string
		baseline Entity
		variants []Entity
	}{
		{
			name:     "Hook",
			baseline: Hook{Event: "PreToolUse", Matcher: "Bash", Command: "echo hi"},
			variants: []Entity{
				Hook{Event: "PostToolUse", Matcher: "Bash", Command: "echo hi"},
				Hook{Event: "PreToolUse", Matcher: "Write", Command: "echo hi"},
				Hook{Event: "PreToolUse", Matcher: "Bash", Command: "echo bye"},
			},
		},
		{
			name:     "MCPServer",
			baseline: MCPServer{Name: "fs", Transport: TransportStdio, Command: "fs-server"},
			variants: []Entity{
				MCPServer{Name: "other", Transport: TransportStdio, Command: "fs-server"},
				MCPServer{Name: "fs", Transport: TransportHTTP, URL: "https://fs-server"},
				MCPServer{Name: "fs", Transport: TransportStdio, Command: "other-server"},
			},
		},
		{
			name:     "EnvVar",
			baseline: EnvVar{Name: "API_KEY", Value: "secret"},
			variants: []Entity{
				EnvVar{Name: "OTHER_KEY", Value: "secret"},
				EnvVar{Name: "API_KEY", Value: "different"},
			},
		},
		{
			name:     "Subagent",
			baseline: Subagent{Name: "reviewer"},
			variants: []Entity{
				Subagent{Name: "planner"},
			},
		},
		{
			name:     "Skill",
			baseline: Skill{Name: "commit-helper"},
			variants: []Entity{
				Skill{Name: "pr-helper"},
			},
		},
		{
			name:     "Plugin",
			baseline: Plugin{Name: "git-helper", Version: "1.0.0"},
			variants: []Entity{
				Plugin{Name: "docker-helper", Version: "1.0.0"},
			},
		},
		{
			name:     "Sandbox",
			baseline: Sandbox{SocketPath: "/tmp/a.sock"},
			variants: []Entity{
				Sandbox{SocketPath: "/tmp/b.sock"},
			},
		},
		{
			name:     "StatusLine",
			baseline: StatusLine{Command: "status.sh", Type: "command"},
			variants: []Entity{
				StatusLine{Command: "other.sh", Type: "command"},
			},
		},
		{
			name:     "CredentialHelper",
			baseline: CredentialHelper{Variant: VariantAPIKeyHelper, Command: "helper.sh"},
			variants: []Entity{
				CredentialHelper{Variant: VariantAWSAuthRefresh, Command: "helper.sh"},
				CredentialHelper{Variant: VariantAPIKeyHelper, Command: "other.sh"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseID := tt.baseline.Identity()
			for i, variant := range tt.variants {
				if variant.Identity() == baseID {
					t.Fatalf("variant %d: Identity() == baseline %q, want distinct", i, baseID)
				}
			}
		})
	}
}

// A non-key field never reaches Identity(), so editing one leaves every id
// already minted from that entity unchanged.
func TestNonKeyFieldsExcludedFromIdentity(t *testing.T) {
	s1 := Subagent{Name: "reviewer", PermissionMode: "default", Tools: []string{"Bash"}}
	s2 := Subagent{Name: "reviewer", PermissionMode: "acceptEdits", Tools: []string{"Write", "Read"}}
	if s1.Identity() != s2.Identity() {
		t.Fatalf("Subagent Identity() differs by non-key fields: %q vs %q", s1.Identity(), s2.Identity())
	}

	h1 := Hook{Event: "PreToolUse", Matcher: "Bash", MCPServer: "release", MCPTool: "publish"}
	h2 := Hook{Event: "PreToolUse", Matcher: "Bash", MCPServer: "audit", MCPTool: "record"}
	if h1.Identity() != h2.Identity() {
		t.Fatalf("Hook Identity() differs by the MCP tool it calls: %q vs %q", h1.Identity(), h2.Identity())
	}

	m1 := MCPServer{Name: "docs", Transport: TransportHTTP, URL: "https://a", HeadersHelper: "./headers.sh"}
	m2 := MCPServer{Name: "docs", Transport: TransportHTTP, URL: "https://a", ForwardedEnv: "DOCS_TOKEN"}
	if m1.Identity() != m2.Identity() {
		t.Fatalf("MCPServer Identity() differs by what the server receives: %q vs %q", m1.Identity(), m2.Identity())
	}

	p1 := Plugin{Name: "git-helper", Version: "1.0.0", Source: "manifest"}
	p2 := Plugin{Name: "git-helper", Version: "2.5.1", Source: "settings"}
	if p1.Identity() != p2.Identity() {
		t.Fatalf("Plugin Identity() differs by Version or Source: %q vs %q", p1.Identity(), p2.Identity())
	}

	pm1 := PermissionMode{Mode: "never", Source: "approval_policy"}
	pm2 := PermissionMode{Mode: "never", Source: "default_permissions"}
	if pm1.Identity() != pm2.Identity() {
		t.Fatalf("PermissionMode Identity() differs by the key that declared it: %q vs %q", pm1.Identity(), pm2.Identity())
	}
}

func TestSandboxFansOutPerSocketPath(t *testing.T) {
	a := Sandbox{SocketPath: "/tmp/one.sock"}
	b := Sandbox{SocketPath: "/tmp/two.sock"}
	if a.Identity() == b.Identity() {
		t.Fatalf("distinct SocketPath values produced the same identity: %q", a.Identity())
	}
}

// A grant keyed on one field must not collide with a grant keyed on
// another, or two capabilities a configuration declares separately dedupe
// into a single finding.
func TestSandboxIdentityDistinguishesEveryGrantForm(t *testing.T) {
	grants := []Sandbox{
		{SocketPath: "/tmp/one.sock"},
		{SocketPath: "mode"},
		{Mode: "insecure_none"},
		{Path: "/etc", Access: "readonly"},
		{Path: "/etc", Access: "readwrite"},
		{Path: "/var", Access: "readonly"},
	}

	seen := map[string]int{}
	for i, grant := range grants {
		id := grant.Identity()
		if prev, dup := seen[id]; dup {
			t.Errorf("grants %d and %d share identity %q", prev, i, id)
		}
		seen[id] = i
	}
}

// A socket grant keys on its socket path and nothing else: the other fields
// sit outside that key, so a socket entry's finding id does not depend on
// them.
func TestSandboxSocketIdentityIsKeyedOnTheSocketPathAlone(t *testing.T) {
	got := Sandbox{SocketPath: "/tmp/agent.sock"}.Identity()
	if want := identity(KindSandbox, "/tmp/agent.sock"); got != want {
		t.Fatalf("Identity() = %q, want %q", got, want)
	}
}

// A fallback action and a pattern are separate egress grants, and two
// patterns are separate from each other.
func TestNetworkPolicyIdentityDistinguishesEveryGrant(t *testing.T) {
	grants := []NetworkPolicy{
		{Default: "allow"},
		{Pattern: "allow"},
		{Pattern: "*.example.com"},
		{Pattern: "registry.example.com"},
	}

	seen := map[string]int{}
	for i, grant := range grants {
		id := grant.Identity()
		if prev, dup := seen[id]; dup {
			t.Errorf("grants %d and %d share identity %q", prev, i, id)
		}
		seen[id] = i
	}
}

// Each entry of a permission list is a grant of its own, so neither half of
// a decomposed entry may settle the identity alone: an entry that carried no
// parseable argument is still a grant, and one argument shared by two tools
// is two grants.
func TestToolPermissionIdentityDistinguishesEveryGrant(t *testing.T) {
	grants := []ToolPermission{
		{Tool: "Shell"},
		{Tool: "Shell", Argument: "*"},
		{Tool: "Shell", Argument: "npm run build"},
		{Tool: "Read", Argument: "*"},
		{Tool: "Write", Argument: "*"},
	}

	seen := map[string]int{}
	for i, grant := range grants {
		id := grant.Identity()
		if prev, dup := seen[id]; dup {
			t.Errorf("grants %d and %d share identity %q", prev, i, id)
		}
		seen[id] = i
	}
}
