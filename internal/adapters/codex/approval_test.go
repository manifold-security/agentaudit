package codex

import (
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// A string policy reaches the entity verbatim; the granular form is named by
// the key that replaced the blanket prompt with per-category toggles.
func TestParseCarriesTheApprovalPolicyItsFileDeclares(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []ir.Entity
	}{
		{
			name: "a blanket policy",
			body: "approval_policy = \"never\"\n",
			want: []ir.Entity{ir.PermissionMode{
				Mode:     "never",
				Source:   "approval_policy",
				Location: ir.Location{File: configFileName, Key: "approval_policy"},
			}},
		},
		{
			name: "a granular policy",
			body: "approval_policy = { granular = { sandbox_approval = true, rules = false } }\n",
			want: []ir.Entity{ir.PermissionMode{
				Mode:     granularKey,
				Source:   "approval_policy",
				Location: ir.Location{File: configFileName, Key: "approval_policy.granular"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS(tt.body))
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Fatalf("Parse() entities = %+v, want %+v", entities, tt.want)
			}
		})
	}
}

// A table carrying no recognised key declares no policy, and says so rather
// than reporting a posture the file never took.
func TestParseDegradesAnApprovalTableItDoesNotRecognise(t *testing.T) {
	entities, warnings, err := New().Parse(configFS("approval_policy = { untrusted = true }\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != configFileName {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, configFileName)
	}
	if got, want := warnings[0].Err.Error(), "approval_policy: expected a table declaring granular, found none"; got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}
}

func TestParseDegradesAnApprovalPolicyOfNeitherForm(t *testing.T) {
	_, warnings, err := New().Parse(configFS("approval_policy = 3\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warnings)
	}
	if got, want := warnings[0].Err.Error(), "approval_policy: expected a string or a table, found a value of another type"; got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}
}
