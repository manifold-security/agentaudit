package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// executableMarker is the one divergence this comparison allows, and
// reportDifferences compares every other field verbatim: a declared
// path-to-bytes set carries no mode bits, so the js/wasm side never sees the
// execute bit report.Describe appends here. Dropping it from the CLI side
// alone keeps the allowance one-directional, so a js/wasm side that started
// emitting the marker fails the comparison rather than being absorbed by it.
const executableMarker = " +x"

// differentialDeadline bounds the js/wasm build and the node instance this
// test drives. A panic inside a js.FuncOf callback wedges the wasm instance
// rather than failing it, and macOS ships no timeout(1) to bound the shell
// instead.
const differentialDeadline = 2 * time.Minute

// differentialDriver instantiates the js/wasm artifact under node and calls
// the published entry point once per job, over a file set read off disk and
// declared under the job's prefix, which is the API a host page uses. It
// writes the envelopes to stdout synchronously, because process.exit drops a
// buffered asynchronous write.
const differentialDriver = `
'use strict';
const nodefs = require('fs');
const nodepath = require('path');

require(process.argv[2]);

function collect(dir, prefix, out) {
  for (const entry of nodefs.readdirSync(dir, { withFileTypes: true })) {
    const abs = nodepath.join(dir, entry.name);
    const rel = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isDirectory()) collect(abs, rel, out);
    else if (entry.isFile()) out[rel] = new Uint8Array(nodefs.readFileSync(abs));
  }
  return out;
}

WebAssembly.instantiate(nodefs.readFileSync(process.argv[3]), (globalThis.go = new Go()).importObject)
  .then((result) => {
    globalThis.go.run(result.instance);
    if (typeof globalThis.agentaudit?.scan !== 'function') {
      console.error('the instance published no scan entry point');
      process.exit(2);
    }
    const jobs = JSON.parse(nodefs.readFileSync(process.argv[4], 'utf8'));
    const envelopes = jobs.map((job) => globalThis.agentaudit.scan(collect(job.dir, job.prefix, {})));
    const payload = Buffer.from(JSON.stringify(envelopes));
    for (let written = 0; written < payload.length; ) {
      written += nodefs.writeSync(1, payload, written, payload.length - written);
    }
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
`

type boundaryJob struct {
	Dir    string `json:"dir"`
	Prefix string `json:"prefix"`
}

// One tree scanned through the JS boundary and through the compiled CLI
// decodes to the same JSON document. Both frontends drive one engine through
// one reporter, so a divergence is a frontend defect and nothing a rule
// change can explain away.
func TestBinaryE2E_TheJSBoundaryAndTheCLIRenderOneReport(t *testing.T) {
	bin := buildAgentauditBinary(t)
	artifact := buildWASMArtifact(t)
	node := nodeBinary(t)
	shim := wasmExecShim(t)
	driver := writeDifferentialDriver(t)

	fixtures := []string{
		capabilitySurfaceFixture,
		cursorCapabilitySurfaceFixture,
		bundledPayloadFixture,
		fullPluginFixture,
		corruptedFixture,
		benignFixture,
	}

	comparedFindings, droppedMarkers := 0, 0
	hostDocs := make(map[string]any, len(fixtures))
	cliDocs := make(map[string]any, len(fixtures))

	jobs := make([]boundaryJob, len(fixtures))
	for i, fixture := range fixtures {
		jobs[i] = boundaryJob{Dir: resolveFixture(t, fixture)}
	}
	envelopes := scanThroughJSBoundary(t, node, driver, shim, artifact, jobs)

	for i, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			host := boundaryReport(t, envelopes[i])
			cli := scanThroughCLI(t, bin, jobs[i].Dir)

			cliFindings, err := reportFindings(cli)
			if err != nil {
				t.Fatalf("CLI document: %v", err)
			}
			if _, err := reportFindings(host); err != nil {
				t.Fatalf("js/wasm document: %v", err)
			}
			comparedFindings += len(cliFindings)

			dropped, err := dropExecutableMarker(cliFindings)
			if err != nil {
				t.Fatalf("CLI document: %v", err)
			}
			droppedMarkers += dropped

			hostDocs[fixture], cliDocs[fixture] = host, cli

			for _, diff := range reportDifferences(host, cli) {
				t.Errorf("%s", diff)
			}
		})
	}

	if comparedFindings == 0 {
		t.Fatalf("no finding was compared, so agreement between the frontends says nothing")
	}
	if droppedMarkers == 0 {
		t.Fatalf("no CLI finding carried %q, so the allowance describes a divergence these trees no longer hold: delete it rather than carry it", executableMarker)
	}

	// The comparison above asserts an absence, so a pair known to differ
	// proves it can report one at all.
	if diffs := reportDifferences(hostDocs[capabilitySurfaceFixture], cliDocs[benignFixture]); len(diffs) == 0 {
		t.Errorf("two different trees compared equal, so the agreement above is vacuous")
	}
}

// buildWASMArtifact compiles the browser frontend for js/wasm, which a host
// go test does not produce.
func buildWASMArtifact(t *testing.T) string {
	t.Helper()

	artifact := filepath.Join(t.TempDir(), "agentaudit.wasm")
	ctx, cancel := context.WithTimeout(context.Background(), differentialDeadline)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build", "-o", artifact, "./wasm")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GOOS=js GOARCH=wasm go build -o %s ./wasm: %v\n%s", artifact, err, out)
	}
	return artifact
}

// nodeBinary fails rather than skips. make check already runs a js/wasm leg
// through node, so node is a prerequisite of the gate, and a skip here would
// drop the cross-frontend comparison without saying so.
func nodeBinary(t *testing.T) string {
	t.Helper()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH, so the js/wasm frontend cannot be driven: %v", err)
	}
	return node
}

// wasmExecShim locates the JS glue the toolchain ships under GOROOT/lib/wasm.
func wasmExecShim(t *testing.T) string {
	t.Helper()

	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	shim := filepath.Join(strings.TrimSpace(string(out)), "lib", "wasm", "wasm_exec.js")
	if _, err := os.Stat(shim); err != nil {
		t.Fatalf("js/wasm exec shim not found at %s: %v", shim, err)
	}
	return shim
}

func writeDifferentialDriver(t *testing.T) string {
	t.Helper()

	driver := filepath.Join(t.TempDir(), "differential.cjs")
	if err := os.WriteFile(driver, []byte(differentialDriver), 0o600); err != nil {
		t.Fatalf("writing the node driver: %v", err)
	}
	return driver
}

func scanThroughJSBoundary(t *testing.T, node, driver, shim, artifact string, jobs []boundaryJob) []map[string]any {
	t.Helper()

	spec, err := json.Marshal(jobs)
	if err != nil {
		t.Fatalf("encoding the driver jobs: %v", err)
	}
	jobFile := filepath.Join(t.TempDir(), "jobs.json")
	if err := os.WriteFile(jobFile, spec, 0o600); err != nil {
		t.Fatalf("writing the driver jobs: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), differentialDeadline)
	defer cancel()

	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, node, driver, shim, artifact, jobFile)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("the js/wasm instance answered nothing within %s\nstderr:\n%s", differentialDeadline, stderr.String())
	}
	if err != nil {
		t.Fatalf("driving the js/wasm frontend over %v: %v\nstderr:\n%s", jobs, err, stderr.String())
	}

	var envelopes []map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &envelopes); err != nil {
		t.Fatalf("decoding the js/wasm envelopes: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if len(envelopes) != len(jobs) {
		t.Fatalf("the js/wasm driver answered %d envelope(s) for %d job(s)", len(envelopes), len(jobs))
	}
	return envelopes
}

func boundaryReport(t *testing.T, envelope map[string]any) any {
	t.Helper()

	if envelope["ok"] != true {
		t.Fatalf("js/wasm envelope ok = %v, error = %v", envelope["ok"], envelope["error"])
	}
	return envelope["report"]
}

func scanThroughCLI(t *testing.T, bin, tree string) any {
	t.Helper()

	stdout, stderr, code := runBinary(t, bin, tree, "-o", "json")
	if code != 0 && code != 1 {
		t.Fatalf("CLI exit code = %d, want a scan outcome rather than a usage or runtime fault\nstderr:\n%s", code, stderr)
	}

	var docs []any
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("decoding the CLI report: %v\nstdout:\n%s", err, stdout)
	}
	if len(docs) != 1 {
		t.Fatalf("the CLI rendered %d documents for one target, want one", len(docs))
	}
	return docs[0]
}

// reportFindings returns doc's findings, refusing any shape the JSON
// reporter does not produce: a silently absent array would let the
// comparison pass over nothing.
func reportFindings(doc any) ([]map[string]any, error) {
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("document is %T, want a JSON object", doc)
	}
	raw, ok := root["findings"].([]any)
	if !ok {
		return nil, fmt.Errorf(`"findings" is %T, want a JSON array`, root["findings"])
	}
	findings := make([]map[string]any, len(raw))
	for i, entry := range raw {
		finding, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("findings[%d] is %T, want a JSON object", i, entry)
		}
		findings[i] = finding
	}
	return findings, nil
}

// dropExecutableMarker removes the allowed divergence from the CLI side and
// reports how many descriptors carried it, so an allowance nothing exercises
// fails loudly instead of sitting unmeasured.
func dropExecutableMarker(findings []map[string]any) (int, error) {
	dropped := 0
	for i, finding := range findings {
		capability, ok := finding["capability"].(map[string]any)
		if !ok {
			return 0, fmt.Errorf("findings[%d].capability is %T, want a JSON object", i, finding["capability"])
		}
		what, ok := capability["what"].(string)
		if !ok {
			return 0, fmt.Errorf("findings[%d].capability.what is %T, want a string", i, capability["what"])
		}
		stripped := strings.ReplaceAll(what, executableMarker, "")
		if stripped != what {
			dropped++
		}
		capability["what"] = stripped
	}
	return dropped, nil
}

// reportDifferences names where two decoded documents disagree, and returns
// nothing when they agree. It compares decoded values rather than encoded
// bytes: both sides run one encoder, so a byte comparison would agree over a
// broken decode and disagree over a harmless field reordering.
func reportDifferences(host, cli any) []string {
	hostDoc, hostOK := host.(map[string]any)
	cliDoc, cliOK := cli.(map[string]any)
	if !hostOK || !cliOK {
		return []string{fmt.Sprintf("js/wasm document is %T and the CLI document is %T, want JSON objects", host, cli)}
	}

	var diffs []string
	for _, key := range []string{"path", "counts"} {
		if !reflect.DeepEqual(hostDoc[key], cliDoc[key]) {
			diffs = append(diffs, fmt.Sprintf("%s: js/wasm = %v, CLI = %v", key, hostDoc[key], cliDoc[key]))
		}
	}

	hostFindings, _ := hostDoc["findings"].([]any)
	cliFindings, _ := cliDoc["findings"].([]any)
	if len(hostFindings) != len(cliFindings) {
		diffs = append(diffs, fmt.Sprintf("findings: js/wasm rendered %d, the CLI rendered %d", len(hostFindings), len(cliFindings)))
	}
	for i := range min(len(hostFindings), len(cliFindings)) {
		diffs = append(diffs, findingDifferences(i, hostFindings[i], cliFindings[i])...)
	}

	if len(diffs) == 0 && !reflect.DeepEqual(hostDoc, cliDoc) {
		diffs = append(diffs, fmt.Sprintf("documents disagree outside path, counts and findings: js/wasm = %v, CLI = %v", hostDoc, cliDoc))
	}
	return diffs
}

// findingDifferences names the disagreeing keys of one finding, so a failure
// reads as a field rather than as two whole documents.
func findingDifferences(index int, host, cli any) []string {
	hostFinding, hostOK := host.(map[string]any)
	cliFinding, cliOK := cli.(map[string]any)
	if !hostOK || !cliOK {
		if reflect.DeepEqual(host, cli) {
			return nil
		}
		return []string{fmt.Sprintf("findings[%d]: js/wasm = %v, CLI = %v", index, host, cli)}
	}

	keys := map[string]bool{}
	for key := range hostFinding {
		keys[key] = true
	}
	for key := range cliFinding {
		keys[key] = true
	}

	var diffs []string
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		if !reflect.DeepEqual(hostFinding[key], cliFinding[key]) {
			diffs = append(diffs, fmt.Sprintf("findings[%d].%s: js/wasm = %v, CLI = %v", index, key, hostFinding[key], cliFinding[key]))
		}
	}
	return diffs
}
