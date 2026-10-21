package mcpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

// ServersFromFile reads a document whose top level carries an mcpServers
// object under key, and returns the decoded entries. A missing file is
// silent; anything else that goes wrong degrades to a Warning so sibling
// sources still parse.
//
// The read goes through fsguard so no caller can reach the bytes without its
// type check first.
func ServersFromFile(fsys fs.FS, file, key string) (map[string]Entry, []adapter.Warning, error) {
	data, err := fsguard.ReadResolvedRegular(fsys, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, []adapter.Warning{{File: file, Err: err}}, nil
	}

	// Invalid JSON falls to the Unmarshal below so its real decode error
	// surfaces; only a valid document of the wrong top level is peeked.
	if json.Valid(data) {
		if f := FormOf(data); f != FormObject && f != FormAbsent {
			return nil, []adapter.Warning{{File: file, Err: errors.New("expected an object, found " + FormName(f))}}, nil
		}
	}

	// The raw value stays undecoded so one wrong-typed entry cannot fail the
	// unmarshal for every sibling.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}, nil
	}

	servers, warnings := ServersFromRaw(doc[key], file, key, limits.Of(fsys))
	return servers, warnings, nil
}

// EntitiesFromFile reads a document whose top level carries an mcpServers
// object under key, and returns the servers it declares that fsys's entity
// budget admits.
func EntitiesFromFile(fsys fs.FS, file, key string, resolve Resolver) ([]ir.Entity, []adapter.Warning, error) {
	servers, warnings, err := ServersFromFile(fsys, file, key)
	if err != nil || servers == nil {
		return nil, warnings, err
	}
	entities, warnings := limits.Of(fsys).Admit(file, Entities(servers, file, key, resolve), warnings)
	return entities, warnings, nil
}

// Entry is one entry within an mcpServers object. "transport" is Claude's
// alternate spelling of "type", decoded here so a Resolver can see both.
// HeadersHelper decodes as `any` so an object or array value degrades to the
// caller's own warning instead of failing this entry's decode; the yaml tag
// is required because yaml.v3 otherwise matches only the lowercased field
// name.
type Entry struct {
	Type          string            `json:"type"`
	Transport     string            `json:"transport"`
	Command       string            `json:"command"`
	Args          []string          `json:"args"`
	Env           map[string]string `json:"env"`
	URL           string            `json:"url"`
	HeadersHelper any               `json:"headersHelper" yaml:"headersHelper"`
}

// Resolver maps an entry onto its transport. The second result feeds
// ir.MCPServer.UnrecognizedTransport, whose doc sets when it may be filled.
type Resolver func(Entry) (ir.Transport, string)

// Form is the shape of a JSON value accepting a string, array or object,
// established by a byte peek rather than a trial decode.
type Form int

const (
	FormAbsent Form = iota // key absent, or explicit null
	FormString             // "./path/to.json"
	FormArray              // ["./a.json", ...] or [{...}, ...]
	FormObject             // inline map
	FormOther              // number/bool -> wrong type, warn + skip
)

// FormName renders f for a warning a config author reads.
func FormName(f Form) string {
	switch f {
	case FormString:
		return "a string"
	case FormArray:
		return "an array"
	case FormObject:
		return "an object"
	case FormAbsent:
		return "nothing"
	default:
		return "a non-object value"
	}
}

// FormOf reads the first non-space byte, so an empty or null value is absent
// rather than a shape.
func FormOf(raw json.RawMessage) Form {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return FormAbsent
	}
	switch trimmed[0] {
	case '"':
		return FormString
	case '[':
		return FormArray
	case '{':
		return FormObject
	default:
		return FormOther
	}
}

// ServersFromRaw decodes a server map per entry so one malformed entry cannot
// blank every sibling, iterating entry names in sorted order because Go map
// iteration is randomized. key prefixes each entry warning, or is "" when raw
// IS the document. Reading stops, and file is refused whole, at the first
// entry budget has no room for.
func ServersFromRaw(raw json.RawMessage, file, key string, budget *limits.Entities) (map[string]Entry, []adapter.Warning) {
	switch f := FormOf(raw); f {
	case FormAbsent:
		return nil, nil
	case FormObject:
		// fall through to the per-entry decode below.
	default:
		msg := "expected an object of server entries, found " + FormName(f)
		if key != "" {
			msg = key + ": " + msg
		}
		return nil, []adapter.Warning{{File: file, Err: errors.New(msg)}}
	}

	rawEntries, over, err := rawServers(raw, budget.Room())
	if err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}
	}
	if over {
		return nil, []adapter.Warning{budget.Refuse(file)}
	}

	names := make([]string, 0, len(rawEntries))
	for name := range rawEntries {
		names = append(names, name)
	}
	sort.Strings(names)

	entryKeyPrefix := key
	if entryKeyPrefix == "" {
		entryKeyPrefix = "mcpServers"
	}

	servers := make(map[string]Entry, len(rawEntries))
	var warnings []adapter.Warning
	for _, name := range names {
		var entry Entry
		if err := json.Unmarshal(rawEntries[name], &entry); err != nil {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s.%s: %w", entryKeyPrefix, name, err)})
			continue
		}
		servers[name] = entry
	}
	return servers, warnings
}

func rawServers(raw json.RawMessage, room int) (entries map[string]json.RawMessage, over bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil, false, err
	}
	entries = map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false, err
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, err
		}
		name, _ := tok.(string)
		entries[name] = value
		if len(entries) > room {
			return nil, true, nil
		}
	}
	return entries, false, nil
}

// Entities converts a decoded mcpServers object into located ir.MCPServer
// entities, sorted by name.
func Entities(servers map[string]Entry, file, keyPrefix string, resolve Resolver) []ir.Entity {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	entities := make([]ir.Entity, 0, len(names))
	for _, name := range names {
		entry := servers[name]
		transport, unrecognized := resolve(entry)
		entities = append(entities, ir.MCPServer{
			Name:                  name,
			Transport:             transport,
			Command:               entry.Command,
			URL:                   entry.URL,
			Args:                  entry.Args,
			Env:                   entry.Env,
			Location:              ir.Location{File: file, Key: keyPrefix + "." + name},
			UnrecognizedTransport: unrecognized,
		})
	}
	return entities
}
