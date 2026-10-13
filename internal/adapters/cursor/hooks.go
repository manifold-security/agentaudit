package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const hooksFileName = ".cursor/hooks.json"

const hooksPayloadDir = ".cursor/hooks"

const payloadOriginHook = "hook"

const hooksKey = "hooks"

const (
	hookTypePrompt = "prompt"

	commandField = "command"
	promptField  = "prompt"
)

// hookEntry is one entry in a hooks.<event> array. The keys it leaves out
// shape how a payload runs rather than whether there is one.
type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Prompt  string `json:"prompt"`
	Matcher string `json:"matcher"`
}

// hookEntities reads the hooks Cursor binds to its lifecycle events,
// degrading per event and per entry so one broken declaration cannot hide its
// siblings.
func hookEntities(fsys fs.FS, file string) ([]ir.Entity, []adapter.Warning, error) {
	doc, warnings := objectDocument(fsys, file)
	if len(warnings) != 0 {
		return nil, warnings, nil
	}

	switch f := mcpjson.FormOf(doc[hooksKey]); f {
	case mcpjson.FormAbsent:
		return nil, nil, nil
	case mcpjson.FormObject:
	default:
		return nil, []adapter.Warning{{File: file, Err: errors.New(hooksKey + ": expected an object of event entries, found " + mcpjson.FormName(f))}}, nil
	}

	var byEvent map[string]json.RawMessage
	if err := json.Unmarshal(doc[hooksKey], &byEvent); err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}, nil
	}

	events := make([]string, 0, len(byEvent))
	for event := range byEvent {
		events = append(events, event)
	}
	sort.Strings(events)

	var entities []ir.Entity
	for _, event := range events {
		eventEntities, eventWarnings := entitiesFromEvent(file, event, byEvent[event])
		entities = append(entities, eventEntities...)
		warnings = append(warnings, eventWarnings...)
	}
	return entities, warnings, nil
}

func entitiesFromEvent(file, event string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	key := hooksKey + "." + event

	if f := mcpjson.FormOf(raw); f != mcpjson.FormArray {
		return nil, []adapter.Warning{{File: file, Err: errors.New(key + ": expected an array of hook entries, found " + mcpjson.FormName(f))}}
	}

	var rawEntries []json.RawMessage
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return nil, []adapter.Warning{{File: file, Err: fmt.Errorf("%s: %w", key, err)}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	for i, rawEntry := range rawEntries {
		entryKey := fmt.Sprintf("%s[%d]", key, i)

		if f := mcpjson.FormOf(rawEntry); f != mcpjson.FormObject {
			warnings = append(warnings, adapter.Warning{File: file, Err: errors.New(entryKey + ": expected an object, found " + mcpjson.FormName(f))})
			continue
		}

		var entry hookEntry
		if err := decodeEntry(entryKey, rawEntry, &entry); err != nil {
			warnings = append(warnings, adapter.Warning{File: file, Err: err})
			continue
		}

		payload, field := hookPayload(entry)
		entities = append(entities, ir.Hook{
			Event:    event,
			Matcher:  entry.Matcher,
			Command:  payload,
			Location: ir.Location{File: file, Key: entryKey + "." + field},
		})
	}
	return entities, warnings
}

// hookPayload resolves what the entry runs and which key declared it.
//
// A declared prompt type wins over a command key that is also present, and an
// entry carrying a prompt alone still fires on its event, so reading command
// alone would report a clean scan over a live hook.
func hookPayload(e hookEntry) (payload, field string) {
	if e.Type == hookTypePrompt || (e.Command == "" && e.Prompt != "") {
		return e.Prompt, promptField
	}
	return e.Command, commandField
}
