package finding

import (
	"reflect"
	"strings"
	"testing"
)

// forbiddenNameFragments are substrings that would indicate a severity,
// score, or risk-level concept has crept into the public surface.
var forbiddenNameFragments = []string{"severity", "score", "risklevel", "risk_level"}

func containsForbiddenFragment(name string) (string, bool) {
	lower := strings.ToLower(name)
	for _, frag := range forbiddenNameFragments {
		if strings.Contains(lower, frag) {
			return frag, true
		}
	}
	return "", false
}

// No exported field of a public finding type names severity or scoring.
func TestNoSeverityInExportedFields(t *testing.T) {
	types := map[string]reflect.Type{
		"Capability":    reflect.TypeOf(Capability{}),
		"Finding":       reflect.TypeOf(Finding{}),
		"Provenance":    reflect.TypeOf(Provenance{}),
		"Report":        reflect.TypeOf(Report{}),
		"Counts":        reflect.TypeOf(Counts{}),
		"CategoryGroup": reflect.TypeOf(CategoryGroup{}),
	}

	fieldsChecked := 0
	for typeName, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			fieldsChecked++
			if frag, bad := containsForbiddenFragment(field.Name); bad {
				t.Fatalf("%s.%s field name contains forbidden fragment %q — severity/score/risk-level is not allowed in the finding package", typeName, field.Name, frag)
			}
		}
	}
	if fieldsChecked == 0 {
		t.Fatalf("no exported fields were checked — guard is not exercising any real struct")
	}
}

// No exported method of Finding or Report names severity or scoring.
func TestNoSeverityInExportedMethods(t *testing.T) {
	types := map[string]reflect.Type{
		"Finding": reflect.TypeOf(Finding{}),
		"Report":  reflect.TypeOf(Report{}),
	}

	methodsChecked := 0
	for typeName, typ := range types {
		for i := 0; i < typ.NumMethod(); i++ {
			method := typ.Method(i)
			methodsChecked++
			if frag, bad := containsForbiddenFragment(method.Name); bad {
				t.Fatalf("%s.%s method name contains forbidden fragment %q — severity/score/risk-level is not allowed in the finding package", typeName, method.Name, frag)
			}
		}
	}
	if methodsChecked == 0 {
		t.Fatalf("no exported methods were checked — guard is not exercising any real type")
	}
}
