package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

// objectDocument reads file as a JSON object keyed by its top-level names. A
// missing file is silent, and a fault degrades to a Warning.
//
// The read goes through fsguard so the entry's type bits are classified
// before anything opens it.
func objectDocument(fsys fs.FS, file string) (map[string]json.RawMessage, []adapter.Warning) {
	return objectDocumentDecoding(fsys, file, keepDecodeFault)
}

// jsoncObjectDocument reads a file Cursor itself decodes with a JSONC
// parser. The decoder here stays strict and reports the gap as its own: a
// comment stripper that misread a slash pair inside a string value would
// turn a scanned file into a report of something the file does not say.
//
// The wording is wrong for a file Cursor decodes strictly, so a file opts
// in by calling this rather than objectDocument.
func jsoncObjectDocument(fsys fs.FS, file string) (map[string]json.RawMessage, []adapter.Warning) {
	return objectDocumentDecoding(fsys, file, jsoncDecodeFault)
}

func objectDocumentDecoding(fsys fs.FS, file string, describe func([]byte, error) error) (map[string]json.RawMessage, []adapter.Warning) {
	data, err := fsguard.ReadResolvedRegular(fsys, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: file, Err: err}}
	}

	// The peek judges only a valid document: an invalid one has to report its
	// own decode error from the Unmarshal below.
	if json.Valid(data) {
		if f := mcpjson.FormOf(data); f != mcpjson.FormObject && f != mcpjson.FormAbsent {
			return nil, []adapter.Warning{{File: file, Err: errors.New("expected an object, found " + mcpjson.FormName(f))}}
		}
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, []adapter.Warning{{File: file, Err: describe(data, err)}}
	}
	return doc, nil
}

func keepDecodeFault(_ []byte, err error) error { return err }

func jsoncDecodeFault(data []byte, err error) error {
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		return err
	}
	at := int(syntax.Offset) - 1
	if at < 0 || at+1 >= len(data) || data[at] != '/' {
		return err
	}
	if next := data[at+1]; next != '/' && next != '*' {
		return err
	}
	return fmt.Errorf("strict JSON decoding stopped at %q (byte %d): Cursor reads this file with a JSONC parser that accepts comments, this scanner does not, so nothing in the file was read", data[at:at+2], at)
}

// decodeEntry decodes one entry object into target, naming the key a
// wrong-typed field sits at. The decoder's own message names the Go struct
// it tried to fill, which means nothing to whoever wrote the JSON.
func decodeEntry(key string, raw json.RawMessage, target any) error {
	err := json.Unmarshal(raw, target)
	if err == nil {
		return nil
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" {
		return fmt.Errorf("%s.%s: expected %s, found %s", key, typeErr.Field, typeErr.Type, typeErr.Value)
	}
	return fmt.Errorf("%s: %w", key, err)
}

// stringValue decodes a JSON string whose form a caller already classified.
func stringValue(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// stringList reads a key whose whole value is an array of strings. A key of
// any other form degrades alone, named by what the array was meant to hold.
func stringList(file, key string, raw json.RawMessage, plural, element string) ([]listElement, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormArray:
	default:
		return nil, []adapter.Warning{{File: file, Err: errors.New(key + ": expected an array of " + plural + ", found " + mcpjson.FormName(f))}}
	}
	return listElements(file, key, raw, element)
}

// listElement is one well-formed string of a JSON array, carrying the
// indexed key its provenance needs.
type listElement struct {
	key   string
	value string
}

// listElements decodes an array of strings, degrading the whole array or one
// element alone so a faulty element never takes its siblings with it. The
// caller's own noun for an element carries into the warning, so a config
// author reads in the terms the key is documented in.
func listElements(file, key string, raw json.RawMessage, element string) ([]listElement, []adapter.Warning) {
	var rawElements []json.RawMessage
	if err := json.Unmarshal(raw, &rawElements); err != nil {
		return nil, []adapter.Warning{{File: file, Err: fmt.Errorf("%s: %w", key, err)}}
	}

	var elements []listElement
	var warnings []adapter.Warning
	for i, rawElement := range rawElements {
		elementKey := fmt.Sprintf("%s[%d]", key, i)

		if f := mcpjson.FormOf(rawElement); f != mcpjson.FormString {
			warnings = append(warnings, adapter.Warning{File: file, Err: errors.New(elementKey + ": expected " + element + ", found " + mcpjson.FormName(f))})
			continue
		}
		elements = append(elements, listElement{key: elementKey, value: stringValue(rawElement)})
	}
	return elements, warnings
}
