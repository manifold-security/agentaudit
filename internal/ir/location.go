package ir

import (
	"reflect"
	"strings"
)

// LocationOf returns e's Location field, resolved by reflection. It mirrors
// match.go's fieldValue guards but selects for Location instead of excluding
// it: reflect.ValueOf(e) → a non-struct Kind short-circuits to the zero
// Location → FieldByNameFunc resolves "Location" case-insensitively → an
// invalid or non-Location field also short-circuits to zero. LocationOf
// never panics.
func LocationOf(e Entity) Location {
	v := reflect.ValueOf(e)
	if v.Kind() != reflect.Struct {
		return Location{}
	}
	fv := v.FieldByNameFunc(func(name string) bool {
		return strings.EqualFold(name, "Location")
	})
	if !fv.IsValid() {
		return Location{}
	}
	loc, ok := fv.Interface().(Location)
	if !ok {
		return Location{}
	}
	return loc
}
