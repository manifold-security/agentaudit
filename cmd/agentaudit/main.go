// Command agentaudit is the CLI frontend: no other package's non-test code
// takes os or Cobra, so the engine and the reporters stay fs.FS-bound.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime/debug"
	"strings"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/registry"
	"github.com/manifold-security/agentaudit/internal/report"
	jsonreport "github.com/manifold-security/agentaudit/internal/report/json"
	"github.com/manifold-security/agentaudit/internal/report/pretty"

	"github.com/spf13/cobra"
)

var scan = func(fsys fs.FS, warn func(error)) (finding.Report, error) {
	sc := agentaudit.New(agentaudit.WithWarnFunc(warn))
	return sc.Scan(fsys)
}

var scanRecursive = func(fsys fs.FS, warn func(error)) ([]agentaudit.ProjectReport, error) {
	sc := agentaudit.New(agentaudit.WithWarnFunc(warn))
	return sc.ScanRecursive(fsys)
}

var scanGlobal = func(fsys fs.FS, warn func(error)) (finding.Report, error) {
	sc := agentaudit.New(agentaudit.WithWarnFunc(warn))
	return sc.ScanGlobal(fsys)
}

func newRootCmd(stdout, stderr io.Writer, code *int) *cobra.Command {
	// Bound directly rather than read back through GetStringArray: pflag's
	// stringArrayValue.String() renders []string{""} as "[]", which its own
	// parser reads back as zero elements, silently dropping --scan-dir "".
	var scanDirs []string
	cmd := &cobra.Command{
		Use:           "agentaudit [PATH]",
		Short:         "Scan an AI agent's configuration for capabilities",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			showVersion, err := cmd.Flags().GetBool("version")
			if err != nil {
				return err
			}
			if showVersion {
				fmt.Fprintf(stdout, "agentaudit %s\n", versionLine(version, commit, debug.ReadBuildInfo))
				*code = 0
				return nil
			}
			format, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}
			if format != "pretty" && format != "json" {
				return fmt.Errorf("agentaudit: %q is not a valid -o value (want \"pretty\" or \"json\"; \"md\" is file-only, use -O md)", format)
			}
			outputFile, err := cmd.Flags().GetString("output-file")
			if err != nil {
				return err
			}
			if outputFile != "" && outputFile != "json" && outputFile != "md" && outputFile != "all" {
				return fmt.Errorf("agentaudit: %q is not a valid -O value (want \"json\", \"md\", or \"all\")", outputFile)
			}
			explain, err := cmd.Flags().GetBool("explain")
			if err != nil {
				return err
			}
			recursive, err := cmd.Flags().GetBool("recursive")
			if err != nil {
				return err
			}
			globalConfig, err := cmd.Flags().GetBool("global-config")
			if err != nil {
				return err
			}

			var targets []string
			if globalConfig {
				if err := globalOnlyConflict(args, scanDirs, recursive); err != nil {
					return err
				}
			} else {
				targets, err = resolveTargets(args, scanDirs)
				if err != nil {
					return err
				}
			}

			warn := func(warnErr error) {
				fmt.Fprintln(stderr, "warning:", report.Escape(warnErr.Error()))
			}

			var blocks []block
			for _, target := range targets {
				tb, err := targetBlocks(target, recursive, warn)
				if err != nil {
					return err
				}
				blocks = append(blocks, tb...)
			}

			var emptyLine string
			if globalConfig {
				gb, unreadable, err := globalBlocks(registry.Adapters(), warn)
				if err != nil {
					return err
				}
				blocks = append(blocks, gb...)
				if len(blocks) == 0 {
					emptyLine = emptyGlobalLine(unreadable)
				}
			}

			if format == "json" {
				if err := jsonreport.Write(stdout, jsonEntries(blocks)); err != nil {
					return err
				}
			} else {
				if emptyLine != "" {
					if _, err := fmt.Fprintln(stdout, emptyLine); err != nil {
						return err
					}
				}
				for i, b := range blocks {
					if i > 0 {
						fmt.Fprintln(stdout)
					}
					if err := pretty.Write(stdout, b.Report, pretty.Meta{Path: b.Path, Explain: explain}); err != nil {
						return err
					}
				}
			}

			if outputFile != "" {
				if err := writeReportFiles(outputFile, blocks, emptyLine); err != nil {
					return err
				}
			}

			hasFindings := false
			for _, b := range blocks {
				if b.Report.HasFindings() {
					hasFindings = true
				}
			}
			if hasFindings {
				*code = 1
			} else {
				*code = 0
			}
			return nil
		},
	}
	cmd.Flags().BoolP("version", "V", false, "print version and exit")
	cmd.Flags().StringP("output", "o", "pretty", "output format: pretty|json")
	cmd.Flags().StringP("output-file", "O", "", "write report file(s): json|md|all (default: write nothing)")
	cmd.Flags().BoolP("explain", "v", false, "show each finding's rule id, message and references (pretty output only)")
	cmd.Flags().StringArrayVar(&scanDirs, "scan-dir", nil, "additional target directory to scan, unioned with PATH (repeatable)")
	cmd.Flags().BoolP("recursive", "r", false, "scan every project beneath each target, one block per project")
	cmd.Flags().Bool("global-config", false, "scan only each adapter's user-level config; cannot be combined with PATH, --scan-dir or -r")
	return cmd
}

type block struct {
	Path   string
	Report finding.Report
}

// run translates the outcome into an exit code: 0 clean, 1 findings present,
// 2 usage or runtime error.
func run(args []string, stdout, stderr io.Writer) int {
	var code int
	cmd := newRootCmd(stdout, stderr, &code)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.Execute(); err != nil {
		if strings.HasPrefix(err.Error(), "agentaudit:") {
			fmt.Fprintln(stderr, report.Escape(err.Error()))
		} else {
			fmt.Fprintln(stderr, "agentaudit:", report.Escape(err.Error()))
		}
		return 2
	}
	return code
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
