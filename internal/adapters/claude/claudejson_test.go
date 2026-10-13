package claude

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestParseGlobal_TopLevelMCPServers(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"mcpServers": {
				"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
				"remote": {"type": "http", "url": "https://mcp.example.com"}
			}
		}`)},
	}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %v, want none", warnings)
	}
	if len(entities) != 2 {
		t.Fatalf("ParseGlobal() entities len = %d, want 2: %+v", len(entities), entities)
	}

	byName := map[string]ir.MCPServer{}
	for _, e := range entities {
		srv, ok := e.(ir.MCPServer)
		if !ok {
			t.Fatalf("entity type = %T, want ir.MCPServer", e)
		}
		byName[srv.Name] = srv
	}

	fsSrv, ok := byName["filesystem"]
	if !ok {
		t.Fatalf("entities = %+v, want a %q server", entities, "filesystem")
	}
	if fsSrv.Transport != ir.TransportStdio {
		t.Errorf("filesystem.Transport = %q, want %q", fsSrv.Transport, ir.TransportStdio)
	}
	if fsSrv.Command != "npx" {
		t.Errorf("filesystem.Command = %q, want %q", fsSrv.Command, "npx")
	}
	if fsSrv.Location != (ir.Location{File: ".claude.json", Key: "mcpServers.filesystem"}) {
		t.Errorf("filesystem.Location = %+v, want %+v", fsSrv.Location, ir.Location{File: ".claude.json", Key: "mcpServers.filesystem"})
	}

	remoteSrv, ok := byName["remote"]
	if !ok {
		t.Fatalf("entities = %+v, want a %q server", entities, "remote")
	}
	if remoteSrv.Transport != ir.TransportHTTP {
		t.Errorf("remote.Transport = %q, want %q", remoteSrv.Transport, ir.TransportHTTP)
	}
	if remoteSrv.URL != "https://mcp.example.com" {
		t.Errorf("remote.URL = %q, want %q", remoteSrv.URL, "https://mcp.example.com")
	}
	if remoteSrv.Location != (ir.Location{File: ".claude.json", Key: "mcpServers.remote"}) {
		t.Errorf("remote.Location = %+v, want %+v", remoteSrv.Location, ir.Location{File: ".claude.json", Key: "mcpServers.remote"})
	}
}

func TestParseGlobal_HeadersHelperCopiesAtBothSurfaces(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"mcpServers": {
				"docs": {"type": "http", "url": "https://mcp.example.test/mcp", "headersHelper": "./scripts/headers.sh"}
			},
			"projects": {
				"/repo/x": {"mcpServers": {"docs": {"type": "http", "url": "https://mcp.example.test/mcp", "headersHelper": "./scripts/headers.sh"}}}
			}
		}`)},
	}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %v, want none", warnings)
	}

	wantKeys := map[string]bool{
		"mcpServers.docs":                                false,
		"mcpServers.docs.headersHelper":                  false,
		"projects./repo/x.mcpServers.docs":               false,
		"projects./repo/x.mcpServers.docs.headersHelper": false,
	}
	for _, e := range entities {
		srv, ok := e.(ir.MCPServer)
		if !ok {
			t.Fatalf("entity type = %T, want ir.MCPServer", e)
		}
		if _, known := wantKeys[srv.Location.Key]; !known {
			t.Fatalf("unexpected Location.Key %q", srv.Location.Key)
		}
		wantKeys[srv.Location.Key] = true
	}
	for key, seen := range wantKeys {
		if !seen {
			t.Errorf("entities = %+v, want an entity keyed %q", entities, key)
		}
	}
}

// Project keys are emitted in sorted order regardless of the document's own
// order, with the project path riding only in Location.Key.
func TestParseGlobal_PerProjectMCPServers(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"projects": {
				"/repo/zeta": {"mcpServers": {"memory": {"command": "npx"}}},
				"/repo/alpha": {"mcpServers": {"memory": {"command": "npx"}}},
				"/repo/mid": {"mcpServers": {"fs": {"command": "npx"}}}
			}
		}`)},
	}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %v, want none", warnings)
	}
	if len(entities) != 3 {
		t.Fatalf("ParseGlobal() entities len = %d, want 3: %+v", len(entities), entities)
	}

	wantKeys := []string{
		"projects./repo/alpha.mcpServers.memory",
		"projects./repo/mid.mcpServers.fs",
		"projects./repo/zeta.mcpServers.memory",
	}
	for i, want := range wantKeys {
		srv, ok := entities[i].(ir.MCPServer)
		if !ok {
			t.Fatalf("entities[%d] type = %T, want ir.MCPServer", i, entities[i])
		}
		if srv.Location.File != claudeJSONFileName || srv.Location.Key != want {
			t.Errorf("entities[%d].Location = %+v, want {%q %q}", i, srv.Location, claudeJSONFileName, want)
		}
	}

	alpha, zeta := entities[0].(ir.MCPServer), entities[2].(ir.MCPServer)
	if alpha.Identity() != zeta.Identity() {
		t.Fatalf("alpha.Identity() = %q, zeta.Identity() = %q, want equal (same server shape, proving Location alone carries the project distinction)", alpha.Identity(), zeta.Identity())
	}
	if alpha.Location.Key == zeta.Location.Key {
		t.Fatalf("alpha and zeta share Location.Key %q, want distinct keys per project", alpha.Location.Key)
	}
}

// A project key that is not an absolute path is emitted as-is in the
// provenance key, never validated, normalized, or resolved.
func TestParseGlobal_ProjectKeyEmittedVerbatim(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"projects": {
				"": {"mcpServers": {"a": {"command": "npx"}}},
				"relative/path": {"mcpServers": {"b": {"command": "npx"}}}
			}
		}`)},
	}

	entities, _, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	got := map[string]bool{}
	for _, e := range entities {
		srv := e.(ir.MCPServer)
		got[srv.Location.Key] = true
	}
	for _, want := range []string{"projects..mcpServers.a", "projects.relative/path.mcpServers.b"} {
		if !got[want] {
			t.Fatalf("Location keys = %v, want %q present verbatim", got, want)
		}
	}
}

// Setting is the bare key name, never prefixed with the project path, which
// is what lets claude.mcp.auto-approve match on setting alone.
func TestParseGlobal_PerProjectEnabledMcpjsonServers(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"projects": {
				"/repo/alpha": {"enabledMcpjsonServers": ["memory", "fs"]}
			}
		}`)},
	}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %v, want none", warnings)
	}
	if len(entities) != 2 {
		t.Fatalf("ParseGlobal() entities len = %d, want 2: %+v", len(entities), entities)
	}

	want := []struct {
		value string
		key   string
	}{
		{"memory", "projects./repo/alpha.enabledMcpjsonServers[0]"},
		{"fs", "projects./repo/alpha.enabledMcpjsonServers[1]"},
	}
	for i, w := range want {
		app, ok := entities[i].(ir.MCPApproval)
		if !ok {
			t.Fatalf("entities[%d] type = %T, want ir.MCPApproval", i, entities[i])
		}
		if app.Setting != "enabledMcpjsonServers" {
			t.Errorf("entities[%d].Setting = %q, want bare %q, never containing the project path", i, app.Setting, "enabledMcpjsonServers")
		}
		if app.Value != w.value {
			t.Errorf("entities[%d].Value = %q, want %q", i, app.Value, w.value)
		}
		if app.Location != (ir.Location{File: claudeJSONFileName, Key: w.key}) {
			t.Errorf("entities[%d].Location = %+v, want {%q %q}", i, app.Location, claudeJSONFileName, w.key)
		}
	}
}

// realisticClaudeJSON carries keys outside the sanctioned set. Values are
// synthetic.
const realisticClaudeJSON = `{
	"numStartups": 42,
	"installMethod": "native",
	"autoUpdates": true,
	"firstStartTime": "2020-01-01T00:00:00.000Z",
	"lastCost": 0.01,
	"announcementImpressions": {"banner": 1},
	"cachedGrowthBookFeatures": {},
	"machineID": "sha256-0000000000000000000000000000000000000000000000000000000000000000",
	"oauthAccount": {"accountUuid": "00000000-0000-0000-0000-000000000000", "emailAddress": "user@example.com"},
	"migrationVersion": 3,
	"lastFpsAverage": 60,
	"lastSessionId": "session-0000",
	"enabledMcpjsonServers": ["top-level-should-be-ignored"],
	"mcpServers": {
		"top-server": {"command": "npx"}
	},
	"projects": {
		"/repo/x": {
			"allowedTools": ["Bash"],
			"hasTrustDialogAccepted": true,
			"mcpContextUris": ["file:///x"],
			"disabledMcpjsonServers": ["blocked-server"],
			"disabledMcpServers": ["blocked-server-2"],
			"history": [{"display": "hi"}],
			"exampleFiles": ["a.txt"],
			"lastCost": 0.02,
			"mcpServers": {"proj-server": {"command": "npx"}},
			"enabledMcpjsonServers": ["proj-approved"]
		}
	}
}`

func TestParseGlobal_UnsurfacedKeysStayOut(t *testing.T) {
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(realisticClaudeJSON)}}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %v, want none", warnings)
	}

	assertUnsurfacedClaudeJSONEntities(t, entities)
}

func wantClaudeJSONEntities() map[string]bool {
	return map[string]bool{
		"MCPServer:top-server:mcpServers.top-server":                          false,
		"MCPServer:proj-server:projects./repo/x.mcpServers.proj-server":       false,
		"MCPApproval:proj-approved:projects./repo/x.enabledMcpjsonServers[0]": false,
	}
}

func claudeJSONEntityKey(t *testing.T, e ir.Entity) string {
	t.Helper()
	switch v := e.(type) {
	case ir.MCPServer:
		return "MCPServer:" + v.Name + ":" + v.Location.Key
	case ir.MCPApproval:
		return "MCPApproval:" + v.Value + ":" + v.Location.Key
	default:
		t.Fatalf("unexpected entity type %T", e)
		return ""
	}
}

// assertUnsurfacedClaudeJSONEntities checks (a) every sanctioned entity is
// present and (b) no entity outside the set exists. Neither half alone proves
// anything: an empty result satisfies (b) trivially.
func assertUnsurfacedClaudeJSONEntities(t *testing.T, entities []ir.Entity) {
	t.Helper()

	want := wantClaudeJSONEntities()

	for _, e := range entities {
		key := claudeJSONEntityKey(t, e)

		if _, sanctioned := want[key]; !sanctioned {
			t.Fatalf("entity %+v (key %q) is outside the sanctioned set %v", e, key, want)
		}
		want[key] = true
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("expected entity %q not found in %+v", k, entities)
		}
	}
}

// A non-regular .claude.json is refused from its mode bits rather than by an
// fs.ReadFile that would block forever on a FIFO with no writer.
func TestParseGlobal_NonRegularFileWarnsWithoutReading(t *testing.T) {
	// Data decodes to a real server, so a guard that read the entry instead of
	// refusing it would surface an entity here.
	validServerJSON := []byte(`{"mcpServers":{"x":{"command":"npx"}}}`)

	tests := []struct {
		name string
		fsys fstest.MapFS
	}{
		{
			name: "FIFO",
			fsys: fstest.MapFS{".claude.json": &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: validServerJSON}},
		},
		{
			name: "directory",
			fsys: fstest.MapFS{".claude.json/settings.json": &fstest.MapFile{Data: validServerJSON}},
		},
		{
			name: "device",
			fsys: fstest.MapFS{".claude.json": &fstest.MapFile{Mode: fs.ModeDevice, Data: validServerJSON}},
		},
		{
			name: "socket",
			fsys: fstest.MapFS{".claude.json": &fstest.MapFile{Mode: fs.ModeSocket, Data: validServerJSON}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().ParseGlobal(tt.fsys)
			if err != nil {
				t.Fatalf("ParseGlobal() error = %v, want nil", err)
			}
			if entities != nil {
				t.Fatalf("ParseGlobal() entities = %v, want nil (a non-regular source is refused, never read)", entities)
			}
			if len(warnings) != 1 || warnings[0].File != claudeJSONFileName {
				t.Fatalf("ParseGlobal() warnings = %v, want exactly one naming %q", warnings, claudeJSONFileName)
			}
			if !strings.Contains(warnings[0].Err.Error(), "not a regular file") {
				t.Fatalf("warning = %q, want it to name the refusal reason, not a JSON decode error", warnings[0].Err)
			}
		})
	}
}

func TestParseGlobal_AbsentFileYieldsNothing(t *testing.T) {
	entities, warnings, err := New().ParseGlobal(fstest.MapFS{})
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if entities != nil {
		t.Fatalf("ParseGlobal() entities = %v, want nil", entities)
	}
	if warnings != nil {
		t.Fatalf("ParseGlobal() warnings = %v, want nil", warnings)
	}
}

// A top-level array warns naming the accepted form, never a Go type name.
func TestParseGlobal_DocumentIsAnArray(t *testing.T) {
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(`[]`)}}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if entities != nil {
		t.Fatalf("ParseGlobal() entities = %v, want nil", entities)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Err.Error(), "an array") {
		t.Fatalf("ParseGlobal() warnings = %v, want exactly one naming the accepted form", warnings)
	}
}

func TestParseGlobal_TruncatedDocument(t *testing.T) {
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(`{"mcpServers":`)}}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if entities != nil {
		t.Fatalf("ParseGlobal() entities = %v, want nil", entities)
	}
	if len(warnings) != 1 {
		t.Fatalf("ParseGlobal() warnings = %v, want exactly 1", warnings)
	}
}

func TestParseGlobal_TopLevelMCPServersWrongTypeStillEmitsProjects(t *testing.T) {
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(`{
		"mcpServers": [],
		"projects": {"/repo/x": {"mcpServers": {"a": {"command": "npx"}}}}
	}`)}}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Err.Error(), "mcpServers") {
		t.Fatalf("ParseGlobal() warnings = %v, want exactly one naming mcpServers", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("ParseGlobal() entities = %+v, want the per-project entity still emitted", entities)
	}
}

func TestParseGlobal_OneProjectValueIsAStringSiblingsStillEmitted(t *testing.T) {
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(`{
		"projects": {
			"/repo/bad": "oops",
			"/repo/good": {"mcpServers": {"a": {"command": "npx"}}}
		}
	}`)}}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Err.Error(), "/repo/bad") {
		t.Fatalf("ParseGlobal() warnings = %v, want exactly one naming projects./repo/bad", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("ParseGlobal() entities = %+v, want the sibling project's entity still emitted", entities)
	}
}

func TestParseGlobal_EnabledMcpjsonServersIsAnObject(t *testing.T) {
	fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(`{
		"projects": {
			"/repo/x": {
				"mcpServers": {"a": {"command": "npx"}},
				"enabledMcpjsonServers": {}
			}
		}
	}`)}}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Err.Error(), "enabledMcpjsonServers") || !strings.Contains(warnings[0].Err.Error(), "an object") {
		t.Fatalf("ParseGlobal() warnings = %v, want exactly one naming enabledMcpjsonServers as an object", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("ParseGlobal() entities = %+v, want the project's mcpServers entity still emitted", entities)
	}
	if _, ok := entities[0].(ir.MCPServer); !ok {
		t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
	}
}

// A link to an ordinary file yields the same entities the file itself would,
// and the chain case pins that resolution follows the link all the way down.
func TestParseGlobal_ReadsASymlinkWhoseTargetIsARegularFile(t *testing.T) {
	const serverJSON = `{"mcpServers":{"x":{"command":"npx"}}}`

	tests := []struct {
		name string
		fsys fstest.MapFS
	}{
		{
			name: "direct link",
			fsys: fstest.MapFS{
				"real.json":    &fstest.MapFile{Data: []byte(serverJSON)},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("real.json")},
			},
		},
		{
			name: "chain of links",
			fsys: fstest.MapFS{
				"real.json":    &fstest.MapFile{Data: []byte(serverJSON)},
				"middle.json":  &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("real.json")},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("middle.json")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().ParseGlobal(tt.fsys)
			if err != nil {
				t.Fatalf("ParseGlobal() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("ParseGlobal() warnings = %v, want none", warnings)
			}
			if len(entities) != 1 {
				t.Fatalf("ParseGlobal() entities = %v, want exactly the target's one server", entities)
			}
			srv, ok := entities[0].(ir.MCPServer)
			if !ok || srv.Name != "x" {
				t.Fatalf("ParseGlobal() entity = %+v, want the ir.MCPServer named x from the link's target", entities[0])
			}
		})
	}
}

// Resolving through a link must not widen what the guard admits, so a link to
// any non-regular form stays refused, and the message names the link's mode.
func TestParseGlobal_RefusesASymlinkWhoseTargetIsNotARegularFile(t *testing.T) {
	const serverJSON = `{"mcpServers":{"x":{"command":"npx"}}}`

	tests := []struct {
		name string
		fsys fstest.MapFS
	}{
		{
			name: "to a FIFO",
			fsys: fstest.MapFS{
				"target":       &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(serverJSON)},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("target")},
			},
		},
		{
			name: "to a directory",
			fsys: fstest.MapFS{
				"target/inner": &fstest.MapFile{Data: []byte(serverJSON)},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("target")},
			},
		},
		{
			name: "to a device",
			fsys: fstest.MapFS{
				"target":       &fstest.MapFile{Mode: fs.ModeDevice, Data: []byte(serverJSON)},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("target")},
			},
		},
		{
			name: "to a socket",
			fsys: fstest.MapFS{
				"target":       &fstest.MapFile{Mode: fs.ModeSocket, Data: []byte(serverJSON)},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("target")},
			},
		},
		{
			name: "dangling",
			fsys: fstest.MapFS{
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("nothing-here.json")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().ParseGlobal(tt.fsys)
			if err != nil {
				t.Fatalf("ParseGlobal() error = %v, want nil", err)
			}
			if entities != nil {
				t.Fatalf("ParseGlobal() entities = %v, want nil (the target is refused, never read)", entities)
			}
			if len(warnings) != 1 || warnings[0].File != claudeJSONFileName {
				t.Fatalf("ParseGlobal() warnings = %v, want exactly one naming %q", warnings, claudeJSONFileName)
			}
			want := `refusing to read ".claude.json": not a regular file (L---------)`
			if got := warnings[0].Err.Error(); got != want {
				t.Fatalf("warning = %q, want %q", got, want)
			}
		})
	}
}

// A dangling link and an absent file are one byte apart in ParseGlobal, which
// treats fs.ErrNotExist as "no global config" and stays silent. A link that
// resolves nowhere is a degraded read the user must see.
func TestParseGlobal_DanglingSymlinkWarnsWhereAnAbsentFileIsSilent(t *testing.T) {
	dangling := fstest.MapFS{
		".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("nothing-here.json")},
	}
	if _, warnings, err := New().ParseGlobal(dangling); err != nil || len(warnings) != 1 {
		t.Fatalf("ParseGlobal(dangling link) warnings = %v, err = %v, want exactly one warning and no error", warnings, err)
	}

	absent := fstest.MapFS{"unrelated.json": &fstest.MapFile{Data: []byte(`{}`)}}
	entities, warnings, err := New().ParseGlobal(absent)
	if err != nil {
		t.Fatalf("ParseGlobal(absent) error = %v, want nil", err)
	}
	if entities != nil || warnings != nil {
		t.Fatalf("ParseGlobal(absent) = (%v, %v), want silence: an absent global config is not a degraded read", entities, warnings)
	}
}

// readLinkOnlyFS reports link modes but withholds fs.StatFS, so a guard
// resolving through fs.Stat would admit the read and this test would see
// entities. The MapFS is a named field rather than embedded: embedding
// promotes its Stat method, which would satisfy fs.StatFS and disarm the test.
type readLinkOnlyFS struct {
	m fstest.MapFS
}

func (f readLinkOnlyFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f readLinkOnlyFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f readLinkOnlyFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

// fs.Stat falls back to Open on an FS without fs.StatFS, and opening a link to
// a FIFO blocks. Asserting the interface is what keeps that resolution out.
func TestParseGlobal_WithoutStatFSRefusesASymlinkRatherThanResolvingIt(t *testing.T) {
	fsys := readLinkOnlyFS{m: fstest.MapFS{
		"real.json":    &fstest.MapFile{Data: []byte(`{"mcpServers":{"x":{"command":"npx"}}}`)},
		".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("real.json")},
	}}

	var probe fs.FS = fsys
	if _, ok := probe.(fs.StatFS); ok {
		t.Fatal("readLinkOnlyFS satisfies fs.StatFS, so it cannot prove the fallback stays closed")
	}

	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if entities != nil {
		t.Fatalf("ParseGlobal() entities = %v, want nil: without fs.StatFS the link is refused, not resolved through a blocking Open", entities)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Err.Error(), "not a regular file") {
		t.Fatalf("ParseGlobal() warnings = %v, want exactly one refusal", warnings)
	}
}

// blockingOpenFS stands in for a FIFO with no writer: Stat answers from the
// type bits while Open never returns.
type blockingOpenFS struct {
	m fstest.MapFS
}

func (f blockingOpenFS) Open(name string) (fs.File, error) {
	select {}
}

func (f blockingOpenFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f blockingOpenFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f blockingOpenFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

// Classification reaches a FIFO through Stat alone, whether the entry is the
// pipe or a link to one; any path that opens it fails here as a deadline.
func TestParseGlobal_AFIFOIsClassifiedWithoutOpening(t *testing.T) {
	const serverJSON = `{"mcpServers":{"x":{"command":"npx"}}}`

	tests := []struct {
		name string
		m    fstest.MapFS
	}{
		{
			name: "the entry is the FIFO",
			m: fstest.MapFS{
				".claude.json": &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(serverJSON)},
			},
		},
		{
			name: "the entry links to the FIFO",
			m: fstest.MapFS{
				"target":       &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(serverJSON)},
				".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("target")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			type result struct {
				entities []ir.Entity
				warnings []adapter.Warning
			}
			done := make(chan result, 1)
			go func() {
				entities, warnings, _ := New().ParseGlobal(blockingOpenFS{m: tt.m})
				done <- result{entities, warnings}
			}()

			select {
			case got := <-done:
				if got.entities != nil {
					t.Fatalf("ParseGlobal() entities = %v, want nil", got.entities)
				}
				if len(got.warnings) != 1 || !strings.Contains(got.warnings[0].Err.Error(), "not a regular file") {
					t.Fatalf("ParseGlobal() warnings = %v, want exactly one refusal", got.warnings)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("ParseGlobal never returned; the guard opened the FIFO instead of stat-ing it")
			}
		})
	}
}
