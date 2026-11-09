package mcpjson

import (
	"reflect"
	"sort"
	"testing"
)

func serverNames(servers map[string]Entry) []string {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// The colliding entry is named in a warning and its sibling server decodes.
func TestServersFromRawDropsAnEntryWhoseKeysDifferOnlyInCase(t *testing.T) {
	servers, warnings := ServersFromRaw([]byte(`{"a":{"command":"x","Command":"y"},"b":{"command":"z"}}`), testFile, "mcpServers", nil)

	if want := []string{"b"}; !reflect.DeepEqual(serverNames(servers), want) {
		t.Errorf("servers = %v, want %v", serverNames(servers), want)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warnings)
	}
	if want := `mcpServers.a: key "Command" differs only in case from "command"`; warnings[0].Err.Error() != want {
		t.Errorf("warning = %q, want %q", warnings[0].Err.Error(), want)
	}
	if warnings[0].File != testFile {
		t.Errorf("warning File = %q, want %q", warnings[0].File, testFile)
	}
}

func TestServersFromRawDropsAnEntryWithAFieldKeyInAnotherCase(t *testing.T) {
	servers, warnings := ServersFromRaw([]byte(`{"a":{"command":"x","Type":"http"},"b":{"command":"z"}}`), testFile, "mcpServers", nil)

	if want := []string{"b"}; !reflect.DeepEqual(serverNames(servers), want) {
		t.Errorf("servers = %v, want %v", serverNames(servers), want)
	}
	if len(warnings) != 1 || warnings[0].Err.Error() != `mcpServers.a: key "Type" differs only in case from "type"` {
		t.Errorf("warnings = %+v, want the one naming Type", warnings)
	}
}

func TestServersFromRawKeepsServerNamesThatDifferOnlyInCase(t *testing.T) {
	servers, warnings := ServersFromRaw([]byte(`{"fs":{"command":"x"},"FS":{"command":"y"}}`), testFile, "mcpServers", nil)

	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	if want := []string{"FS", "fs"}; !reflect.DeepEqual(serverNames(servers), want) {
		t.Errorf("servers = %v, want %v", serverNames(servers), want)
	}
	if servers["fs"].Command != "x" || servers["FS"].Command != "y" {
		t.Errorf("servers = %+v, want each name to keep its own command", servers)
	}
}
