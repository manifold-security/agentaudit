package tomlconf

import (
	"errors"
	"io/fs"

	"github.com/pelletier/go-toml/v2"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
)

// Document reads file as a TOML document keyed by its top-level names. A
// missing file is silent; anything else that goes wrong degrades to a
// Warning so sibling sources still parse.
func Document(fsys fs.FS, file string) (map[string]any, []adapter.Warning) {
	data, err := fsguard.ReadResolvedRegular(fsys, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: file, Err: err}}
	}

	// The generic target leaves the decoder with syntax to report and no Go
	// type to name.
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}
	}
	return doc, nil
}

// Form is the shape of a decoded TOML value, established by its Go type.
type Form int

const (
	FormAbsent Form = iota // key absent
	FormString             // "workspace-write"
	FormBool               // true
	FormArray              // ["/etc", ...]
	FormTable              // a header table or an inline one
	FormOther              // a number or a moment
)

// FormName renders f for a warning a config author reads.
func FormName(f Form) string {
	switch f {
	case FormString:
		return "a string"
	case FormBool:
		return "a boolean"
	case FormArray:
		return "an array"
	case FormTable:
		return "a table"
	case FormAbsent:
		return "nothing"
	default:
		return "a value of another type"
	}
}

// FormOf classifies v, the value a decoded document holds under one key.
func FormOf(v any) Form {
	switch v.(type) {
	case nil:
		return FormAbsent
	case string:
		return FormString
	case bool:
		return FormBool
	case []any:
		return FormArray
	case map[string]any:
		return FormTable
	default:
		return FormOther
	}
}
