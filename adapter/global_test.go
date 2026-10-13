package adapter

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

type stubGlobalAdapter struct{ stubAdapter }

func (stubGlobalAdapter) GlobalConfig() GlobalConfig {
	return GlobalConfig{Base: BaseHome, Entries: []string{".claude"}}
}

func (stubGlobalAdapter) ParseGlobal(fs.FS) ([]ir.Entity, []Warning, error) {
	return nil, nil, nil
}

func TestGlobalScoped_AdapterPlusGlobalConfigSatisfiesIt(t *testing.T) {
	if _, ok := any(stubGlobalAdapter{}).(GlobalScoped); !ok {
		t.Fatalf("stubGlobalAdapter does not satisfy GlobalScoped")
	}
}

// GlobalScoped stays optional instead of widening Adapter itself.
func TestGlobalScoped_AdapterAloneDoesNotSatisfyIt(t *testing.T) {
	if _, ok := any(stubAdapter{}).(GlobalScoped); ok {
		t.Fatalf("stubAdapter satisfies GlobalScoped, want it not to")
	}
}

type bareGlobalConfig struct{}

func (bareGlobalConfig) GlobalConfig() GlobalConfig { return GlobalConfig{} }

func TestGlobalScoped_GlobalConfigAloneDoesNotSatisfyIt(t *testing.T) {
	if _, ok := any(bareGlobalConfig{}).(GlobalScoped); ok {
		t.Fatalf("bareGlobalConfig satisfies GlobalScoped, want it not to")
	}
}

// A path or "~" value would smuggle a filesystem spelling into this package
// as data, sidestepping the "os" import ban rather than honouring it.
func TestBaseHome_IsATokenNotAPath(t *testing.T) {
	if BaseHome == "" {
		t.Fatalf("BaseHome is empty, want a non-empty token")
	}
	if strings.ContainsAny(string(BaseHome), "/\\~") {
		t.Fatalf("BaseHome = %q, want no path separator and no %q", BaseHome, "~")
	}
}
