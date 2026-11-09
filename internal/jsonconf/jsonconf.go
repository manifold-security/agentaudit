package jsonconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Unmarshal decodes data into v as json.Unmarshal does, and fails when a key
// of an object matches a struct field of v only by ignoring case.
func Unmarshal(data []byte, v any) error {
	return UnmarshalAt(data, v, "")
}

// UnmarshalAt is Unmarshal for a value that sits at path within a larger
// document, so a key's message names the path from that document's root.
func UnmarshalAt(data []byte, v any, path string) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	err := check(data, reflect.TypeOf(v))
	if path != "" {
		err = within(err, path)
	}
	return err
}

type keyCase struct {
	steps      []string
	key, field string
}

func (c *keyCase) Error() string {
	var path strings.Builder
	for i := len(c.steps) - 1; i >= 0; i-- {
		if step := c.steps[i]; strings.HasPrefix(step, "[") || path.Len() == 0 {
			path.WriteString(step)
		} else {
			path.WriteString("." + step)
		}
	}
	msg := fmt.Sprintf("key %+q differs only in case from %+q", c.key, c.field)
	if path.Len() == 0 {
		return msg
	}
	return path.String() + ": " + msg
}

func within(err error, step string) error {
	var c *keyCase
	if errors.As(err, &c) {
		c.steps = append(c.steps, step)
	}
	return err
}

type field struct {
	name  string
	bytes []byte
	typ   reflect.Type
}

// check reads raw as already valid JSON, which json.Unmarshal has established
// before UnmarshalAt calls it.
func check(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		return checkStruct(raw, t)
	case reflect.Map:
		return each(raw, '{', func(key, value []byte) error {
			if err := check(value, t.Elem()); err != nil {
				return within(err, string(unescaped(key)))
			}
			return nil
		})
	case reflect.Slice, reflect.Array:
		index := 0
		return each(raw, '[', func(_, value []byte) error {
			if err := check(value, t.Elem()); err != nil {
				return within(err, fmt.Sprintf("[%d]", index))
			}
			index++
			return nil
		})
	}
	return nil
}

func checkStruct(raw []byte, t reflect.Type) error {
	fields, err := fieldsOf(t)
	if err != nil {
		return err
	}
	return each(raw, '{', func(rawKey, value []byte) error {
		key := unescaped(rawKey)
		i := slotOf(fields, key)
		if i < 0 {
			return nil
		}
		if fields[i].name != string(key) {
			return &keyCase{key: string(key), field: fields[i].name}
		}
		if err := check(value, fields[i].typ); err != nil {
			return within(err, string(key))
		}
		return nil
	})
}

func slotOf(fields []field, key []byte) int {
	for i, f := range fields {
		if f.name == string(key) {
			return i
		}
	}
	for i, f := range fields {
		if bytes.EqualFold(f.bytes, key) {
			return i
		}
	}
	return -1
}

func fieldsOf(t reflect.Type) ([]field, error) {
	var fields []field
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			return nil, fmt.Errorf("embedded field %s of %s is not supported", f.Name, t)
		}
		if !f.IsExported() {
			continue
		}
		tag, _ := f.Tag.Lookup("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		fields = append(fields, field{name: name, bytes: []byte(name), typ: f.Type})
	}
	return fields, nil
}

func unescaped(key []byte) []byte {
	if bytes.IndexByte(key, '\\') < 0 {
		return key
	}
	var s string
	_ = json.Unmarshal(append(append([]byte{'"'}, key...), '"'), &s)
	return []byte(s)
}

// each visits the members of raw if it opens with open. A key reaches visit as
// written, escapes included and quotes excluded.
func each(raw []byte, open byte, visit func(key, value []byte) error) error {
	i := skipSpace(raw, 0)
	if i == len(raw) || raw[i] != open {
		return nil
	}
	for i = skipSpace(raw, i+1); i < len(raw) && raw[i] != '}' && raw[i] != ']'; {
		var key []byte
		if open == '{' {
			end := stringEnd(raw, i)
			key = raw[i+1 : end]
			i = skipSpace(raw, skipSpace(raw, end+1)+1)
		}
		end := valueEnd(raw, i)
		if err := visit(key, raw[i:end]); err != nil {
			return err
		}
		i = skipSpace(raw, end)
		if i < len(raw) && raw[i] == ',' {
			i = skipSpace(raw, i+1)
		}
	}
	return nil
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	return min(i, len(b))
}

func stringEnd(b []byte, start int) int {
	for i := start + 1; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return len(b)
}

func valueEnd(b []byte, start int) int {
	if start >= len(b) {
		return len(b)
	}
	switch b[start] {
	case '"':
		return min(stringEnd(b, start)+1, len(b))
	case '{', '[':
		depth := 0
		for i := start; i < len(b); i++ {
			switch b[i] {
			case '"':
				i = stringEnd(b, i)
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return i + 1
				}
			}
		}
		return len(b)
	}
	if end := bytes.IndexAny(b[start+1:], ",]} \t\r\n"); end >= 0 {
		return start + 1 + end
	}
	return len(b)
}
