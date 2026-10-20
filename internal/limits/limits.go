// Package limits holds what a scan's limits share with the code they bound
// and the frontend that tunes them.
package limits

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"reflect"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// The defaults a scan's limits start from.
const (
	DefaultFileSize  int64 = 512 << 10
	DefaultReadBytes int64 = 64 << 20
	DefaultEntities        = 10000
)

// ErrLimit is the sentinel the scan's file, read, entity, depth and alias
// limits wrap in a refusal.
var ErrLimit = errors.New("refused by a scan limit")

// The sentinels a refusal wraps to name the limit that refused it.
var (
	ErrFileSize   = fmt.Errorf("file size %w", ErrLimit)
	ErrReadBudget = fmt.Errorf("read budget %w", ErrLimit)
	ErrEntities   = fmt.Errorf("entities %w", ErrLimit)
)

// Refusal returns an error reading msg that wraps ErrLimit.
func Refusal(msg string) error { return RefusalBy(ErrLimit, msg) }

// RefusalBy returns an error reading msg that wraps limit.
func RefusalBy(limit error, msg string) error { return refusal{msg: msg, limit: limit} }

type refusal struct {
	msg   string
	limit error
}

func (r refusal) Error() string { return r.msg }

func (r refusal) Unwrap() error { return r.limit }

// JSONDepthRefusal returns err as a refusal when it is encoding/json giving
// up past its nesting depth, which a JavaScript agent's JSON.parse reads
// past, and err itself otherwise.
func JSONDepthRefusal(err error) error {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) && strings.HasSuffix(syntax.Error(), jsonDepthExceeded) {
		return depthRefusal{err}
	}
	return err
}

const jsonDepthExceeded = "exceeded max depth"

type depthRefusal struct{ error }

func (d depthRefusal) Unwrap() []error { return []error{d.error, ErrLimit} }

// Faults wraps err, one fault standing for n malformed items, so Admit
// charges all n.
func Faults(n int, err error) error { return counted{error: err, n: n} }

type counted struct {
	error
	n int
}

func (c counted) Unwrap() error { return c.error }

// FaultCount reports how many malformed items err stands for: the n Faults
// gave it, or one.
func FaultCount(err error) int {
	var c counted
	if errors.As(err, &c) {
		return c.n
	}
	return 1
}

// Entities is the entity budget of one adapter's parse. An entity spends one
// plus one per value of its slice and map fields, and a malformed item spends
// one. A nil *Entities admits everything.
type Entities struct {
	max, used int
	refused   map[string]bool
}

// NewEntities returns a budget of n entities, or nil when n <= 0.
func NewEntities(n int) *Entities {
	if n <= 0 {
		return nil
	}
	return &Entities{max: n, refused: map[string]bool{}}
}

// Carrier is an fs.FS that hands its parsers an entity budget.
type Carrier interface {
	fs.FS
	EntityBudget() *Entities
}

// Of returns the budget fsys carries, or nil when it carries none.
func Of(fsys fs.FS) *Entities {
	if c, ok := fsys.(Carrier); ok {
		return c.EntityBudget()
	}
	return nil
}

// Room reports what b has left to spend.
func (b *Entities) Room() int {
	if b == nil {
		return math.MaxInt
	}
	return b.max - b.used
}

// Admit spends b on file's entities and on the malformed items its warnings
// report, returning both or, when they would pass what b has left, refusing
// file whole: no entities, and its refusal in place of its warnings. A
// refusal among the warnings costs nothing.
func (b *Entities) Admit(file string, entities []ir.Entity, warnings []adapter.Warning) ([]ir.Entity, []adapter.Warning) {
	if b == nil {
		return entities, warnings
	}
	charge := 0
	for _, e := range entities {
		charge += weight(e)
	}
	for _, w := range warnings {
		if !errors.Is(w.Err, ErrLimit) {
			charge += FaultCount(w.Err)
		}
	}
	if refusal, ok := b.Spend(file, charge); !ok {
		return nil, []adapter.Warning{refusal}
	}
	return entities, warnings
}

// Spend spends n of b on file's items or, when they would pass what b has
// left or b already refused file, refuses file whole and returns that
// refusal.
func (b *Entities) Spend(file string, n int) (adapter.Warning, bool) {
	if b == nil {
		return adapter.Warning{}, true
	}
	if n > b.Room() || b.refused[file] {
		return b.Refuse(file), false
	}
	b.used += n
	return adapter.Warning{}, true
}

func weight(e ir.Entity) int {
	n := 1
	v := reflect.ValueOf(e)
	if v.Kind() != reflect.Struct {
		return n
	}
	for i := range v.NumField() {
		switch f := v.Field(i); f.Kind() {
		case reflect.Slice, reflect.Map:
			n += f.Len()
		}
	}
	return n
}

// Refuse marks file refused whole in a non-nil b and returns the warning
// that says so.
func (b *Entities) Refuse(file string) adapter.Warning {
	b.refused[file] = true
	return adapter.Warning{File: file, Err: RefusalBy(ErrEntities, fmt.Sprintf("would take the scan past %d entities; not scanned", b.max))}
}

// Keep drops the entities of every file b refused, those Admit kept before
// the refusal included.
func (b *Entities) Keep(entities []ir.Entity) []ir.Entity {
	if b == nil || len(b.refused) == 0 {
		return entities
	}
	kept := entities[:0]
	for _, e := range entities {
		if !b.refused[ir.LocationOf(e).File] {
			kept = append(kept, e)
		}
	}
	return kept
}

// KeepWarnings drops every warning of a file b refused except its refusals,
// whether the warning came before the refusal or after it.
func (b *Entities) KeepWarnings(ws []adapter.Warning) []adapter.Warning {
	if b == nil || len(b.refused) == 0 {
		return ws
	}
	kept := ws[:0]
	for _, w := range ws {
		if !b.refused[w.File] || errors.Is(w.Err, ErrLimit) {
			kept = append(kept, w)
		}
	}
	return kept
}
