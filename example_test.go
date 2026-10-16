package agentaudit_test

import (
	"fmt"
	"log"
	"os"

	"github.com/manifold-security/agentaudit"
)

func ExampleScanner_Scan() {
	root, err := os.OpenRoot("testdata/malicious/claude-guardrail")
	if err != nil {
		log.Fatal(err)
	}
	defer root.Close()

	report, err := agentaudit.New().Scan(root.FS())
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range report.Findings() {
		fmt.Println(f.RuleID, f.Digest())
	}
	fmt.Println("unreadable:", report.UnreadableSources(), "unparsed:", report.UnparsedSources())
	// Output:
	// claude.mcp.auto-approve f7a854ac0ccbd4e08a0ebd3bbf0c5345
	// claude.mcp.auto-approve 8a417358847b405d2014612d29ca2117
	// claude.permissions.permissive-default-mode 9cf00b737c2a6dd5633ec3b433ea7bdb
	// claude.sandbox.dangerous-socket cb7a282d87e0184f20a81029dd40a635
	// claude.sandbox.unix-socket e2c3052e0d4a985f490ec80707bc781f
	// unreadable: 0 unparsed: 0
}
