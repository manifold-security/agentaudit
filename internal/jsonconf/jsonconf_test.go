package jsonconf

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type commandDoc struct {
	Command string `json:"command"`
}

type allowDoc struct {
	Allow json.RawMessage `json:"allow"`
}

type untaggedDoc struct {
	Configurations json.RawMessage
}

type hooksDoc struct {
	Hooks map[string]string `json:"hooks"`
}

type hookGroup struct {
	Hooks []commandDoc `json:"hooks"`
}

type groupsDoc struct {
	Hooks map[string][]hookGroup `json:"hooks"`
}

type permissionsDoc struct {
	Permissions *struct {
		DefaultMode *string `json:"defaultMode"`
	} `json:"permissions"`
}

type envDoc struct {
	Env map[string]string `json:"env"`
}

type unexportedDoc struct {
	command string
	Other   string `json:"other"`
}

type optionOnlyDoc struct {
	Mode string `json:",omitempty"`
}

type skippedDoc struct {
	Skipped commandDoc `json:"-"`
	Other   string     `json:"other"`
}

type Embedded struct {
	Command string `json:"command"`
}

type embeddingDoc struct {
	Embedded
}

// A decode error is json.Unmarshal's own, byte for byte, so a caller that
// matches or prints it sees the same text.
func TestUnmarshalReturnsTheDecodeErrorUnchanged(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"not json", `not json`},
		{"trailing data", `{"command":"a"} x`},
		{"a comment", "{\"command\":\"a\"} // note"},
		{"a type error", `{"command":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want, got commandDoc
			wantErr := json.Unmarshal([]byte(tc.doc), &want)
			if wantErr == nil {
				t.Fatalf("premise: json.Unmarshal(%q) error = nil, want one", tc.doc)
			}
			gotErr := Unmarshal([]byte(tc.doc), &got)
			if gotErr == nil || gotErr.Error() != wantErr.Error() || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
				t.Errorf("Unmarshal(%q) error = %#v, want %#v", tc.doc, gotErr, wantErr)
			}
		})
	}
}

// A key that matches a field only ignoring case fails the document, and the
// message names the key as it decodes, escaped when it is not ASCII.
func TestUnmarshalFailsOnKeysThatDifferOnlyInCase(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		into      func() any
		want      string
	}{
		{"a tagged field", `{"command":"a","Command":"b"}`, func() any { return new(commandDoc) },
			`key "Command" differs only in case from "command"`},
		{"a raw message field", `{"allow":["x"],"Allow":null}`, func() any { return new(allowDoc) },
			`key "Allow" differs only in case from "allow"`},
		{"an untagged field", `{"configurations":[],"Configurations":null}`, func() any { return new(untaggedDoc) },
			`key "configurations" differs only in case from "Configurations"`},
		{"neither key is the field's own spelling", `{"HOOKS":{},"Hooks":{}}`, func() any { return new(hooksDoc) },
			`key "HOOKS" differs only in case from "hooks"`},
		{"an option-only tag", `{"mode":"a","Mode":"b"}`, func() any { return new(optionOnlyDoc) },
			`key "mode" differs only in case from "Mode"`},
		{"a key folding through a non-ASCII letter", `{"hooks":{},"hook\u017f":null}`, func() any { return new(hooksDoc) },
			`key "hook\u017f" differs only in case from "hooks"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(tc.doc), tc.into()); err != nil {
				t.Fatalf("premise: json.Unmarshal(%s) error = %v, want nil", tc.doc, err)
			}
			err := Unmarshal([]byte(tc.doc), tc.into())
			if err == nil || err.Error() != tc.want {
				t.Errorf("Unmarshal(%s) error = %v, want %q", tc.doc, err, tc.want)
			}
		})
	}
}

func TestUnmarshalFailsOnAKeyThatMatchesAFieldOnlyIgnoringCase(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"a lone key", `{"COMMAND":"a"}`, `key "COMMAND" differs only in case from "command"`},
		{"an escaped key", `{"\u0043ommand":"a"}`, `key "Command" differs only in case from "command"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc commandDoc
			if err := json.Unmarshal([]byte(tc.doc), &doc); err != nil || doc.Command != "a" {
				t.Fatalf("premise: json.Unmarshal(%s) = %+v, %v, want the value read", tc.doc, doc, err)
			}
			err := Unmarshal([]byte(tc.doc), &commandDoc{})
			if err == nil || err.Error() != tc.want {
				t.Errorf("Unmarshal(%s) error = %v, want %q", tc.doc, err, tc.want)
			}
		})
	}
}

func TestUnmarshalAcceptsAnEscapedKeyThatIsExact(t *testing.T) {
	var doc commandDoc
	if err := Unmarshal([]byte(`{"comm\u0061nd":"a"}`), &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}
	if doc.Command != "a" {
		t.Errorf("Command = %q, want %q", doc.Command, "a")
	}
}

// A document json.Unmarshal refuses reports that refusal, not a key finding.
func TestUnmarshalReportsTheDecodeErrorBeforeAKeyFinding(t *testing.T) {
	const doc = `{"Command":1}`
	want := json.Unmarshal([]byte(doc), &commandDoc{})
	if want == nil {
		t.Fatalf("premise: json.Unmarshal(%s) error = nil, want a type error", doc)
	}
	if got := Unmarshal([]byte(doc), &commandDoc{}); got == nil || got.Error() != want.Error() {
		t.Errorf("Unmarshal(%s) error = %v, want %v", doc, got, want)
	}
}

// An exact duplicate key is accepted and decodes as json.Unmarshal reads
// it: the last value wins.
func TestUnmarshalAcceptsAnExactDuplicateKey(t *testing.T) {
	var doc commandDoc
	if err := Unmarshal([]byte(`{"command":"a","command":"b"}`), &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}
	if doc.Command != "b" {
		t.Errorf("Command = %q, want %q", doc.Command, "b")
	}
}

// A key below the top level names the document path it sits at.
func TestUnmarshalNamesThePathOfANestedCaseCollision(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		into      func() any
		want      string
	}{
		{"a struct in a slice in a map", `{"hooks":{"SessionStart":[{"hooks":[{"command":"a","Command":"b"}]}]}}`,
			func() any { return new(groupsDoc) },
			`hooks.SessionStart[0].hooks[0]: key "Command" differs only in case from "command"`},
		{"a struct behind a pointer", `{"permissions":{"defaultMode":"a","DefaultMode":"b"}}`,
			func() any { return new(permissionsDoc) },
			`permissions: key "DefaultMode" differs only in case from "defaultMode"`},
		{"a slice at the top", `[{"command":"a"},{"command":"a","Command":"b"}]`,
			func() any { return new([]commandDoc) },
			`[1]: key "Command" differs only in case from "command"`},
		{"an array at the top", `[{"command":"a"},{"command":"a","Command":"b"}]`,
			func() any { return new([2]commandDoc) },
			`[1]: key "Command" differs only in case from "command"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(tc.doc), tc.into()); err != nil {
				t.Fatalf("premise: json.Unmarshal(%s) error = %v, want nil", tc.doc, err)
			}
			err := Unmarshal([]byte(tc.doc), tc.into())
			if err == nil || err.Error() != tc.want {
				t.Errorf("Unmarshal(%s) error = %v, want %q", tc.doc, err, tc.want)
			}
		})
	}
}

// Keys of a map member are names, not field spellings, so two that differ
// only in case stay two entries.
func TestUnmarshalKeepsMapKeysThatDifferOnlyInCase(t *testing.T) {
	var env envDoc
	if err := Unmarshal([]byte(`{"env":{"PATH":"a","path":"b"}}`), &env); err != nil {
		t.Fatalf("Unmarshal(env) error = %v, want nil", err)
	}
	if want := map[string]string{"PATH": "a", "path": "b"}; !reflect.DeepEqual(env.Env, want) {
		t.Errorf("Env = %v, want %v", env.Env, want)
	}

	var groups groupsDoc
	doc := `{"hooks":{"SessionStart":[{"hooks":[{"command":"a"}]}],"sessionStart":[{"hooks":[{"command":"b"}]}]}}`
	if err := Unmarshal([]byte(doc), &groups); err != nil {
		t.Fatalf("Unmarshal(hooks) error = %v, want nil", err)
	}
	if len(groups.Hooks) != 2 {
		t.Errorf("len(Hooks) = %d, want 2", len(groups.Hooks))
	}
}

// encoding/json skips an unexported field, so a key matching one is no
// mismatch.
func TestUnmarshalIgnoresUnexportedFields(t *testing.T) {
	var doc unexportedDoc
	if err := Unmarshal([]byte(`{"command":"a","Command":"b","other":"c"}`), &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}
	if doc.Other != "c" || doc.command != "" {
		t.Errorf("doc = %+v, want only Other set", doc)
	}
}

// A target embedding a struct promotes its fields in ways the key check does
// not model, so the document fails instead of passing unchecked.
func TestUnmarshalRefusesAnEmbeddedField(t *testing.T) {
	var doc embeddingDoc
	err := Unmarshal([]byte(`{"command":"a"}`), &doc)
	if want := "embedded field Embedded of jsonconf.embeddingDoc is not supported"; err == nil || err.Error() != want {
		t.Errorf("Unmarshal() error = %v, want %q", err, want)
	}
}

func TestUnmarshalIgnoresAFieldTaggedOut(t *testing.T) {
	var doc skippedDoc
	if err := Unmarshal([]byte(`{"-":{"command":"a","Command":"b"},"other":"c"}`), &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}
	if doc.Other != "c" || doc.Skipped != (commandDoc{}) {
		t.Errorf("doc = %+v, want only Other set", doc)
	}
}

// each reports the members encoding/json's own decoder reads.
func TestEachReportsWhatTheDecoderReads(t *testing.T) {
	for _, doc := range []string{
		`{}`,
		` { } `,
		`{"a":1,"b":"x","c":null,"d":true,"e":-1.5e3}`,
		"{ \"a\" : [ 1 , { \"b\" : \"]}\" } ] ,\n\"c\":{\"d\":{}} }",
		`{"k\"ey":"v\\","\u00e9":"\"","nested":[[],[{}],"a,b"]}`,
		`{"a":"\\\"","b":2}`,
	} {
		t.Run(doc, func(t *testing.T) {
			var got, want []string
			_ = each([]byte(doc), '{', func(key, value []byte) error {
				got = append(got, string(unescaped(key))+"="+string(value))
				return nil
			})

			dec := json.NewDecoder(strings.NewReader(doc))
			if _, err := dec.Token(); err != nil {
				t.Fatalf("premise: Token() error = %v", err)
			}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					t.Fatalf("premise: Token() error = %v", err)
				}
				var value json.RawMessage
				if err := dec.Decode(&value); err != nil {
					t.Fatalf("premise: Decode() error = %v", err)
				}
				want = append(want, key.(string)+"="+string(value))
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("each(%s) = %q, want %q", doc, got, want)
			}
		})
	}
}

func TestEachReportsTheElementsOfAnArray(t *testing.T) {
	var got []string
	_ = each([]byte(` [ 1 , "a]" , [2,3] , {"b":[]} ] `), '[', func(key, value []byte) error {
		if key != nil {
			t.Errorf("key = %q, want none for an array element", key)
		}
		got = append(got, string(value))
		return nil
	})
	if want := []string{`1`, `"a]"`, `[2,3]`, `{"b":[]}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("elements = %q, want %q", got, want)
	}
}

// A value that does not open with the delimiter asked for holds nothing to
// visit, while one that does is visited.
func TestEachVisitsNothingInAValueOfAnotherForm(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		open      byte
	}{
		{"null as an object", `null`, '{'},
		{"a string as an object", `"abc"`, '{'},
		{"an array as an object", `[1,2]`, '{'},
		{"an object as an array", `{"a":1}`, '['},
		{"nothing at all", ``, '{'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = each([]byte(tc.raw), tc.open, func(key, value []byte) error {
				t.Errorf("visited %q = %q, want nothing", key, value)
				return nil
			})
		})
	}

	visited := 0
	_ = each([]byte(`{"a":1}`), '{', func(_, _ []byte) error { visited++; return nil })
	if visited != 1 {
		t.Errorf("visited = %d, want 1 for an object holding one member", visited)
	}
}

// check stays in bounds on a document cut short at any byte.
func TestCheckStaysInBoundsOnAnyTruncation(t *testing.T) {
	doc := []byte(` {"hooks":{"a\"b":[{"hooks":[{"command":"x\\","Command":1.5e3,"z":[true,null]}]}]},"allow":"s"} `)
	for n := range len(doc) + 1 {
		for _, typ := range []reflect.Type{reflect.TypeFor[groupsDoc](), reflect.TypeFor[[]commandDoc](), reflect.TypeFor[map[string]commandDoc](), reflect.TypeFor[string]()} {
			_ = check(doc[:n], typ)
		}
	}
	if err := check(doc, reflect.TypeFor[groupsDoc]()); err == nil {
		t.Errorf("check(whole document) error = nil, want the nested collision")
	}
}

// A value decoded from within a larger document names the path it sits at, so
// the caller's message reads from the document's root.
func TestUnmarshalAtPrefixesTheCollisionPath(t *testing.T) {
	for _, tc := range []struct {
		name, at, want string
	}{
		{"a document path", "hooks", `hooks.SessionStart[0].hooks[0]: key "Command" differs only in case from "command"`},
		{"no path", "", `SessionStart[0].hooks[0]: key "Command" differs only in case from "command"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string][]hookGroup
			err := UnmarshalAt([]byte(`{"SessionStart":[{"hooks":[{"command":"a","Command":"b"}]}]}`), &doc, tc.at)
			if err == nil || err.Error() != tc.want {
				t.Errorf("UnmarshalAt() error = %v, want %q", err, tc.want)
			}
		})
	}
}
