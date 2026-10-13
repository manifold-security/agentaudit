//go:build js && wasm

// Command wasm publishes a synchronous scan entry point on the JS global,
// over a filesystem the host declares as a path-to-bytes set.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"syscall/js"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/internal/hostroot"
	"github.com/manifold-security/agentaudit/internal/memfs"
	"github.com/manifold-security/agentaudit/internal/registry"
	"github.com/manifold-security/agentaudit/internal/report"
	reportjson "github.com/manifold-security/agentaudit/internal/report/json"
)

const namespace = "agentaudit"

// hostPath labels the scanned root in the rendered report. A declared file
// set has no location of its own to name.
const hostPath = "."

// executableBitLimit identifies the blind spot a path-to-bytes set carries
// by construction, so a caller can branch on it without matching prose.
const executableBitLimit = "no-executable-bit"

func main() {
	install()

	// A main that returns tears the instance down and the entry point dies
	// with it, so the boundary blocks for the life of the host page.
	select {}
}

func install() js.Func {
	fn := js.FuncOf(scan)
	ns := js.Global().Get("Object").New()
	ns.Set("scan", fn)
	js.Global().Set(namespace, ns)
	return fn
}

func scan(_ js.Value, args []js.Value) any {
	files, err := hostFiles(args)
	if err != nil {
		return fatal(err, nil)
	}
	// Vetted before rebasing, so a refusal names the path the host declared.
	if _, err := memfs.New(files); err != nil {
		return fatal(fmt.Errorf("agentaudit: scan: %w", err), nil)
	}
	rooted, err := hostroot.Rebase(files, registry.Adapters())
	if err != nil {
		return fatal(fmt.Errorf("agentaudit: scan: %w", err), nil)
	}
	fsys, err := memfs.New(rooted)
	if err != nil {
		return fatal(fmt.Errorf("agentaudit: scan: %w", err), nil)
	}
	return envelope(fsys, rooted)
}

// hostFiles copies the declared bytes into Go. Each value crosses as a
// Uint8Array and a JS string is refused rather than coerced: a string
// crosses as UTF-16 and the conversion back silently repairs invalid UTF-8,
// destroying what report.Escape exists to surface before the scanner reads a
// byte of it.
func hostFiles(args []js.Value) (map[string][]byte, error) {
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return nil, errors.New("agentaudit: scan: want one argument, an object mapping each path to its bytes")
	}

	src := args[0]
	uint8Array := js.Global().Get("Uint8Array")
	names := js.Global().Get("Object").Call("keys", src)

	files := make(map[string][]byte, names.Length())
	for i := range names.Length() {
		name := names.Index(i).String()
		value := src.Get(name)
		if !value.InstanceOf(uint8Array) {
			return nil, fmt.Errorf("agentaudit: scan: %s: want a Uint8Array, got %s", name, value.Type())
		}
		data := make([]byte, value.Get("length").Int())
		js.CopyBytesToGo(data, value)
		files[name] = data
	}
	return files, nil
}

func envelope(fsys fs.FS, files map[string][]byte) map[string]any {
	var warnings []any
	emit := func(err error) { warnings = append(warnings, report.Escape(err.Error())) }

	doc, err := scanned(fsys, files, emit)
	if err != nil {
		return fatal(err, warnings)
	}

	return map[string]any{
		"ok":       true,
		"report":   doc,
		"warnings": warnings,
		"limits":   hostLimits(),
	}
}

func scanned(fsys fs.FS, files map[string][]byte, emit func(error)) (js.Value, error) {
	rep, err := agentaudit.New(agentaudit.WithWarnFunc(emit)).Scan(fsys)
	if err != nil {
		return js.Undefined(), err
	}
	if err := verifySighted(fsys, files); err != nil {
		return js.Undefined(), err
	}
	return render(rep)
}

func verifySighted(fsys fs.FS, files map[string][]byte) error {
	if len(files) == 0 {
		return errors.New("agentaudit: scan: no file declared, so the scan was blind to the whole tree")
	}

	sighted := 0
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if _, declared := files[name]; declared && !entry.IsDir() {
			sighted++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("agentaudit: scan: walking the declared filesystem: %w", err)
	}
	if sighted != len(files) {
		return fmt.Errorf("agentaudit: scan: a walk reached %d of the %d declared files, so the scan was blind to the rest", sighted, len(files))
	}
	return nil
}

// render routes the report through the JSON reporter and hands the host the
// decoded document, keeping one authority for the wire shape.
func render(rep agentaudit.Report) (js.Value, error) {
	var buf bytes.Buffer
	entries := []reportjson.Entry{{Report: rep, Meta: reportjson.Meta{Path: hostPath}}}
	if err := reportjson.Write(&buf, entries); err != nil {
		return js.Undefined(), fmt.Errorf("agentaudit: render: %w", err)
	}
	return js.Global().Get("JSON").Call("parse", buf.String()).Index(0), nil
}

// hostLimits names what the host cannot observe, as a property of the host
// rather than of the scanned tree. Folding it into the report's own
// UnreadableSources tally would claim an attacker-chosen blind spot where
// there is only a channel that carries no mode bits.
func hostLimits() []any {
	return []any{
		map[string]any{
			"id":     executableBitLimit,
			"detail": "a declared file carries no execute bit, so no finding is marked executable and an extensionless payload with no shebang is not collected",
		},
	}
}

// fatal renders an unusable scan. Warnings already emitted travel with it,
// because the host has no other channel to hear them on.
func fatal(err error, warnings []any) map[string]any {
	return map[string]any{
		"ok":       false,
		"error":    report.Escape(err.Error()),
		"warnings": warnings,
		"limits":   hostLimits(),
	}
}
