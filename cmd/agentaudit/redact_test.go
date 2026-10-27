package main

import (
	"bytes"
	"html"
	"io"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

const cliCanary = "c4n4ry0secret"

type capturedFile struct{ *bytes.Buffer }

func (capturedFile) Close() error { return nil }

func credentialTargetFS() fstest.MapFS {
	return fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers": {
			"remote": {"type": "http", "url": "https://u:` + cliCanary + `@mcp.example.test/mcp?api_key=` + cliCanary + `"},
			"args": {"command": "npx", "args": ["--token", "` + cliCanary + `"]}
		}}`)},
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{
			"env": {"HTTPS_PROXY": "http://me:` + cliCanary + `@proxy.example.test:3128"},
			"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "FOO_TOKEN=` + cliCanary + ` ./run.sh"}]}]}
		}`)},
	}
}

var (
	prettyMaskedArgs = regexp.MustCompile(`npx --token \*\*\*`)
	jsonMaskedArgs   = regexp.MustCompile(`"--token",\s*"\*\*\*"`)
)

// Neither stdout nor a report file carries a credential the scanned config
// declared, and each still shows where the masked value points.
func TestRun_PrintsNoCredentialOnStdoutOrInAReportFile(t *testing.T) {
	visible := []string{"https://***@mcp.example.test/mcp?api_key=***", "http://***@proxy.example.test:3128", "FOO_TOKEN=*** ./run.sh"}

	for _, tc := range []struct {
		args    []string
		outputs map[string]*regexp.Regexp
	}{
		{[]string{"-v", "-O", "all", "tgt"}, map[string]*regexp.Regexp{"stdout": prettyMaskedArgs, jsonReportFilename: jsonMaskedArgs, mdReportFilename: nil}},
		{[]string{"-o", "json", "tgt"}, map[string]*regexp.Regexp{"stdout": jsonMaskedArgs}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			withOpenTarget(t, map[string]fs.FS{"tgt": credentialTargetFS()})
			files := map[string]*bytes.Buffer{}
			original := createFile
			createFile = func(name string) (io.WriteCloser, error) {
				files[name] = &bytes.Buffer{}
				return capturedFile{files[name]}, nil
			}
			t.Cleanup(func() { createFile = original })

			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != 1 {
				t.Fatalf("run(%q) = %d, want 1\nstderr: %s", tc.args, code, stderr.String())
			}
			wantFiles := len(tc.outputs) - 1
			if len(files) != wantFiles {
				t.Fatalf("run(%q) wrote %d report files, want %d besides stdout", tc.args, len(files), wantFiles)
			}
			for name, masked := range tc.outputs {
				out := stdout.String()
				if name != "stdout" {
					b, ok := files[name]
					if !ok {
						t.Fatalf("run(%q) wrote no %s", tc.args, name)
					}
					out = b.String()
				}
				shown := out
				if name == mdReportFilename {
					shown = html.UnescapeString(out)
				}
				if strings.Contains(out, cliCanary) || strings.Contains(shown, cliCanary) {
					t.Errorf("%s carries the secret %q:\n%s", name, cliCanary, out)
				}
				for _, want := range visible {
					if !strings.Contains(shown, want) {
						t.Errorf("%s lacks %q:\n%s", name, want, shown)
					}
				}
				if masked != nil && !masked.MatchString(out) {
					t.Errorf("%s lacks the masked argument %s:\n%s", name, masked, out)
				}
			}
		})
	}
}
