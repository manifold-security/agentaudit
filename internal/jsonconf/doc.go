// Package jsonconf decodes a JSON configuration document into a Go value.
// encoding/json matches an object's keys to struct fields whatever their
// case, so a key can reach a field it does not name; this package reports such
// a document as an error.
package jsonconf
