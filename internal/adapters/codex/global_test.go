package codex

import (
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
)

func TestGlobalConfigDeclaresEveryCodexHomeEntry(t *testing.T) {
	cfg := New().GlobalConfig()
	if cfg.Base != adapter.BaseHome {
		t.Fatalf("GlobalConfig().Base = %q, want %q", cfg.Base, adapter.BaseHome)
	}
	want := map[string]bool{
		configFileName: true,
		hooksFileName:  true,
		skillsRoot:     true,
	}
	got := map[string]bool{}
	for _, e := range cfg.Entries {
		got[e] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GlobalConfig().Entries = %v, want exactly %v", cfg.Entries, want)
	}
}
