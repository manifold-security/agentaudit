package limits_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

func hooksIn(file string, n int) []ir.Entity {
	entities := make([]ir.Entity, n)
	for i := range entities {
		entities[i] = ir.Hook{Command: "x", Location: ir.Location{File: file}}
	}
	return entities
}

func faultsIn(file string, n int) []adapter.Warning {
	warnings := make([]adapter.Warning, n)
	for i := range warnings {
		warnings[i] = adapter.Warning{File: file, Err: fmt.Errorf("item %d: malformed", i)}
	}
	return warnings
}

func TestAdmitSpendsTheBudgetUpToItsLastEntity(t *testing.T) {
	b := limits.NewEntities(3)

	if got, _ := b.Admit("a", hooksIn("a", 2), nil); len(got) != 2 {
		t.Fatalf("Admit(a, 2 entities) kept %d, want 2", len(got))
	}
	got, warnings := b.Admit("b", hooksIn("b", 2), nil)
	if got != nil {
		t.Errorf("Admit(b, 2 entities) past the budget kept %d, want none", len(got))
	}
	if kept, _ := b.Admit("c", hooksIn("c", 1), nil); len(kept) != 1 {
		t.Errorf("Admit(c, 1 entity) at the budget kept %d, want 1", len(kept))
	}
	if got := b.Room(); got != 0 {
		t.Errorf("Room() = %d, want 0", got)
	}

	if len(warnings) != 1 || warnings[0].File != "b" {
		t.Fatalf("warnings = %+v, want one naming b", warnings)
	}
	if got, want := warnings[0].Err.Error(), "would take the scan past 3 entities; not scanned"; got != want {
		t.Errorf("refusal = %q, want %q", got, want)
	}
	if !errors.Is(warnings[0].Err, limits.ErrLimit) {
		t.Errorf("refusal %q does not wrap ErrLimit", warnings[0].Err)
	}
}

// A file's faults spend the budget beside its entities, and a refused file
// gives up its faults to the one refusal that replaces them.
func TestAdmitChargesAFileItsFaults(t *testing.T) {
	for _, tc := range []struct {
		budget  int
		refused bool
	}{
		{3, false},
		{2, true},
	} {
		t.Run(fmt.Sprint(tc.budget), func(t *testing.T) {
			b := limits.NewEntities(tc.budget)
			faults := faultsIn("a", 2)
			entities, warnings := b.Admit("a", hooksIn("a", 1), faults)

			if tc.refused {
				if entities != nil || len(warnings) != 1 || !errors.Is(warnings[0].Err, limits.ErrLimit) {
					t.Errorf("Admit() = %v, %v, want no entity and the refusal alone", entities, warnings)
				}
				return
			}
			if len(entities) != 1 || !slices.Equal(warnings, faults) || b.Room() != 0 {
				t.Errorf("Admit() = %v, %v, Room() = %d, want the entity, its faults and 0", entities, warnings, b.Room())
			}
		})
	}
}

func TestAdmitChargesEachFaultACountedWarningCarries(t *testing.T) {
	counted := adapter.Warning{File: "a", Err: fmt.Errorf("frontmatter: %w", limits.Faults(4, errors.New("four faults")))}
	for _, tc := range []struct {
		budget  int
		refused bool
	}{
		{4, false},
		{3, true},
	} {
		t.Run(fmt.Sprint(tc.budget), func(t *testing.T) {
			_, warnings := limits.NewEntities(tc.budget).Admit("a", nil, []adapter.Warning{counted})
			if got := errors.Is(warnings[0].Err, limits.ErrLimit); got != tc.refused {
				t.Errorf("Admit() warnings = %v, refused = %v, want %v", warnings, got, tc.refused)
			}
		})
	}
	if got := limits.FaultCount(counted.Err); got != 4 {
		t.Errorf("FaultCount(counted) = %d, want 4", got)
	}
	if got := limits.FaultCount(errors.New("one")); got != 1 {
		t.Errorf("FaultCount(plain) = %d, want 1", got)
	}
}

func TestAdmitChargesEachValueAnEntityHolds(t *testing.T) {
	server := []ir.Entity{ir.MCPServer{Args: []string{"a", "b"}, Env: map[string]string{"K": "v"}, Location: ir.Location{File: "a"}}}
	for _, tc := range []struct {
		budget  int
		refused bool
	}{
		{4, false},
		{3, true},
	} {
		t.Run(fmt.Sprint(tc.budget), func(t *testing.T) {
			if got, _ := limits.NewEntities(tc.budget).Admit("a", server, nil); (got == nil) != tc.refused {
				t.Errorf("Admit(server with 3 values) at %d kept %v, want refused %v", tc.budget, got, tc.refused)
			}
		})
	}
}

type nameEntity string

func (nameEntity) Kind() string       { return "name" }
func (n nameEntity) Identity() string { return string(n) }

func TestAdmitChargesAnEntityThatIsNoStructOne(t *testing.T) {
	b := limits.NewEntities(2)
	if got, _ := b.Admit("a", []ir.Entity{nameEntity("x")}, nil); len(got) != 1 || b.Room() != 1 {
		t.Errorf("Admit(one non-struct entity) kept %d with Room() = %d, want 1 and 1", len(got), b.Room())
	}
}

// A file already refused spends nothing more, and a refusal handed back to
// Admit costs nothing, so neither crowds out a later file that fits.
func TestAdmitSpendsNothingOnARefusedFileOrARefusal(t *testing.T) {
	b := limits.NewEntities(3)
	_, refusal := b.Admit("a", hooksIn("a", 4), nil)
	if got, warnings := b.Admit("a", hooksIn("a", 1), refusal); got != nil || !slices.Equal(warnings, refusal) || b.Room() != 3 {
		t.Errorf("Admit(refused a) = %v, %v with Room() = %d, want only its refusal and 3", got, warnings, b.Room())
	}
	if got, warnings := b.Admit("b", hooksIn("b", 2), []adapter.Warning{{File: "b", Err: limits.Refusal("a limit")}}); len(got) != 2 || len(warnings) != 1 || b.Room() != 1 {
		t.Errorf("Admit(b with a refusal) = %v, %v with Room() = %d, want both entities, the refusal and 1", got, warnings, b.Room())
	}
	if got, _ := b.Admit("c", hooksIn("c", 1), nil); len(got) != 1 {
		t.Errorf("Admit(c) at the budget kept %d, want 1", len(got))
	}
}

// A file refused after spending keeps its spend, so the room it leaves
// cannot admit more than it holds.
func TestRefuseKeepsWhatTheRefusedFileSpent(t *testing.T) {
	b := limits.NewEntities(5)
	b.Admit("a", hooksIn("a", 2), nil)
	if _, ok := b.Spend("a", 4); ok || b.Room() != 3 {
		t.Errorf("Spend(a, 4) admitted = %v with Room() = %d, want refused and 3", ok, b.Room())
	}
	if got, _ := b.Admit("b", hooksIn("b", 4), nil); got != nil {
		t.Errorf("Admit(b, 4 entities) with 3 left kept %d, want none", len(got))
	}
}

func TestKeepDropsEveryEntityOfARefusedFile(t *testing.T) {
	b := limits.NewEntities(2)
	kept, _ := b.Admit("a", hooksIn("a", 1), nil)
	more, _ := b.Admit("b", hooksIn("b", 1), nil)
	kept = append(kept, more...)
	more, _ = b.Admit("a", hooksIn("a", 1), nil)
	kept = append(kept, more...)

	if got := b.Keep(kept); !slices.Equal(got, hooksIn("b", 1)) {
		t.Errorf("Keep() = %+v, want b's entity alone", got)
	}
}

// Only the refused file loses its warnings: another file's warnings stand
// beside the refusal.
func TestKeepWarningsDropsEveryOtherWarningOfARefusedFile(t *testing.T) {
	b := limits.NewEntities(1)
	before, after, other := faultsIn("a", 1), faultsIn("a", 1), faultsIn("b", 1)
	_, refusal := b.Admit("a", hooksIn("a", 2), nil)

	got := b.KeepWarnings(slices.Concat(before, refusal, after, other))
	if want := slices.Concat(refusal, other); !slices.Equal(got, want) {
		t.Errorf("KeepWarnings() = %+v, want %+v", got, want)
	}
}

// Only encoding/json's own depth failure becomes a refusal: a warning that
// merely reads like one stays apart from ErrLimit.
func TestJSONDepthRefusalTakesOnlyTheDecodersDepthError(t *testing.T) {
	var deep any
	depthErr := json.Unmarshal([]byte(strings.Repeat("[", 10001)+strings.Repeat("]", 10001)), &deep)
	var malformed any
	syntaxErr := json.Unmarshal([]byte("{not json"), &malformed)

	for _, tc := range []struct {
		name    string
		err     error
		limited bool
	}{
		{"the decoder's depth error", fmt.Errorf("settings.json: %w", depthErr), true},
		{"another syntax error", syntaxErr, false},
		{"a stub with the same text", errors.New("frontmatter: exceeded max depth"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := limits.JSONDepthRefusal(tc.err)
			if errors.Is(got, limits.ErrLimit) != tc.limited || got.Error() != tc.err.Error() {
				t.Errorf("JSONDepthRefusal(%q) = %q, ErrLimit %v, want the same text and ErrLimit %v", tc.err, got, errors.Is(got, limits.ErrLimit), tc.limited)
			}
		})
	}
}

func TestANilBudgetAdmitsEverything(t *testing.T) {
	for _, n := range []int{0, -1} {
		b := limits.NewEntities(n)
		if b != nil {
			t.Fatalf("NewEntities(%d) = %+v, want nil", n, b)
		}
		faults := faultsIn("a", 3)
		if got, warnings := b.Admit("a", hooksIn("a", 5), faults); len(got) != 5 || !slices.Equal(warnings, faults) {
			t.Errorf("nil Admit() = %d entities, warnings %+v, want 5 and the faults", len(got), warnings)
		}
		if got := b.Room(); got != math.MaxInt {
			t.Errorf("nil Room() = %d, want math.MaxInt", got)
		}
		if got := b.Keep(hooksIn("a", 2)); len(got) != 2 {
			t.Errorf("nil Keep() = %d entities, want 2", len(got))
		}
		if got := b.KeepWarnings(faults); !slices.Equal(got, faults) {
			t.Errorf("nil KeepWarnings() = %+v, want the faults", got)
		}
	}
}

type budgetFS struct {
	m fstest.MapFS
	b *limits.Entities
}

func (f budgetFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f budgetFS) EntityBudget() *limits.Entities { return f.b }

func TestOfFindsTheBudgetAnFSCarries(t *testing.T) {
	b := limits.NewEntities(1)
	if got := limits.Of(budgetFS{m: fstest.MapFS{}, b: b}); got != b {
		t.Errorf("Of(carrier) = %p, want %p", got, b)
	}
	if got := limits.Of(fstest.MapFS{}); got != nil {
		t.Errorf("Of(MapFS) = %p, want nil", got)
	}
}
