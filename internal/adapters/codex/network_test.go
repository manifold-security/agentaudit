package codex

import (
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func proxyLocation(key string) ir.Location {
	return ir.Location{File: configFileName, Key: "features.network_proxy." + key}
}

// Each grant the proxy table makes reaches its own entity, carrying the key
// that declared it: one entity for the table would name a single grant and
// drop the rest.
func TestParseFansOutOneEntityPerNetworkProxyGrant(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[features.network_proxy]\n" +
			"enabled = true\n" +
			"allow_local_binding = true\n" +
			"allow_upstream_proxy = true\n" +
			"dangerously_allow_all_unix_sockets = true\n" +
			"dangerously_allow_non_loopback_proxy = true\n" +
			"proxy_url = \"http://127.0.0.1:3128\"\n" +
			"\n[features.network_proxy.domains]\n" +
			"\"**.example.com\" = \"allow\"\n" +
			"\"tracking.example.net\" = \"deny\"\n" +
			"\n[features.network_proxy.unix_sockets]\n" +
			"\"/var/run/docker.sock\" = \"allow\"\n" +
			"\"/tmp/old.sock\" = \"deny\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	want := []ir.Entity{
		ir.NetworkPolicy{Pattern: "**.example.com", Location: proxyLocation("domains.**.example.com")},
		ir.Sandbox{SocketPath: "/var/run/docker.sock", Location: proxyLocation("unix_sockets./var/run/docker.sock")},
		ir.NetworkPolicy{Default: localBindingKey, Location: proxyLocation(localBindingKey)},
		ir.NetworkPolicy{Default: allUnixSocketsKey, Location: proxyLocation(allUnixSocketsKey)},
		ir.NetworkPolicy{Default: nonLoopbackProxyKey, Location: proxyLocation(nonLoopbackProxyKey)},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A guard the file leaves standing declares no capability. The granted arm
// is what proves the withheld one is a choice rather than a parser that
// reads nothing.
func TestParseSurfacesANetworkProxyGuardOnlyWhereItIsLifted(t *testing.T) {
	const lifted = "[features.network_proxy]\nallow_local_binding = true\n"
	const standing = "[features.network_proxy]\nallow_local_binding = false\n"

	entities, warnings, err := New().Parse(configFS(lifted))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.NetworkPolicy{
		Default:  localBindingKey,
		Location: proxyLocation(localBindingKey),
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}

	entities, warnings, err = New().Parse(configFS(standing))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want none: a guard left standing grants nothing", entities)
	}
}

// The proxy table's guard keys also exist under a permission profile's
// network table, and a configuration writing them there reaches the report
// under the profile's own key.
func TestParseReadsTheNetworkGuardsUnderAProfileToo(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.hardened.network]\n" +
			"allow_local_binding = true\n" +
			"allow_upstream_proxy = true\n" +
			"dangerously_allow_all_unix_sockets = true\n" +
			"dangerously_allow_non_loopback_proxy = true\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	const key = "permissions.hardened.network."
	want := []ir.Entity{
		ir.NetworkPolicy{Default: localBindingKey, Location: ir.Location{File: configFileName, Key: key + localBindingKey}},
		ir.NetworkPolicy{Default: allUnixSocketsKey, Location: ir.Location{File: configFileName, Key: key + allUnixSocketsKey}},
		ir.NetworkPolicy{Default: nonLoopbackProxyKey, Location: ir.Location{File: configFileName, Key: key + nonLoopbackProxyKey}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// Neither web-search key widens what a repository can reach: the mode picks
// a retrieval backend, and allowed_domains restricts the hosts the search
// may use. The proxy grant beside them keeps the expected report non-empty.
func TestParseLeavesTheWebSearchKeysOutOfTheReport(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"web_search = \"live\"\n" +
			"\n[features.network_proxy]\n" +
			"allow_local_binding = true\n" +
			"\n[tools.web_search]\n" +
			"allowed_domains = [\"docs.example.org\", \"*.example.net\"]\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	want := []ir.Entity{ir.NetworkPolicy{
		Default:  localBindingKey,
		Location: proxyLocation(localBindingKey),
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want the proxy grant alone %+v", entities, want)
	}
}

// A wrong-typed key degrades alone, named by the full dotted key and by what
// that key was meant to hold, and the grant beside it still reaches the
// report. enabled is read under a permission profile and not in the proxy
// table, so the wrong-typed one here draws neither warning nor entity.
func TestParseDegradesAWrongTypedNetworkKeyAlone(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[features.network_proxy]\n" +
			"enabled = \"yes\"\n" +
			"domains = \"*\"\n" +
			"allow_local_binding = true\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil: a malformed key degrades", err)
	}

	var got []string
	for _, w := range warnings {
		if w.File != configFileName {
			t.Errorf("warning %+v does not name %q", w, configFileName)
		}
		got = append(got, w.Err.Error())
	}
	want := []string{
		"features.network_proxy.domains: expected a table, found a string",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %+v, want %+v", got, want)
	}

	wantEntities := []ir.Entity{
		ir.NetworkPolicy{Default: localBindingKey, Location: proxyLocation(localBindingKey)},
	}
	if !reflect.DeepEqual(entities, wantEntities) {
		t.Fatalf("Parse() entities = %+v, want the well-formed grant %+v", entities, wantEntities)
	}
}
