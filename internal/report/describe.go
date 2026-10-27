package report

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// autoStartEvents are Hook Events that fire without any user action.
var autoStartEvents = map[string]bool{
	"SessionStart":     true,
	"UserPromptSubmit": true,
	"PreToolUse":       true,
}

// Describe annotates what (an auto-start hook, a referenced payload, and so
// on) with facts about the capability, never a severity or risk level.
func Describe(e ir.Entity) (what, value string) {
	what, value = describe(e)
	return Redact(what), Redact(value)
}

func describe(e ir.Entity) (what, value string) {
	switch v := e.(type) {
	case ir.Hook:
		if v.MCPTool != "" {
			return hookLine(v), fmt.Sprintf("mcp_tool server=%q tool=%q", v.MCPServer, v.MCPTool)
		}
		return hookLine(v), v.Command
	case ir.MCPServer:
		if v.HeadersHelper != "" {
			return mcpDestinationLine(v, "headers helper for"), v.HeadersHelper
		}
		if v.ForwardedEnv != "" {
			return mcpDestinationLine(v, "env sent to"), v.ForwardedEnv
		}
		label := string(v.Transport)
		if v.UnrecognizedTransport != "" {
			label += fmt.Sprintf(" inferred; declared %q", v.UnrecognizedTransport)
		}
		if primary, secondary, secondaryLabel := mcpEndpointFields(v); primary != "" && secondary != "" {
			label += fmt.Sprintf("; %s=%q", secondaryLabel, secondary)
		}
		what = fmt.Sprintf("mcpServer %s (%s)", v.Name, label)
		return what, mcpEndpoints(v)
	case ir.EnvVar:
		if v.Value != "" && credentialVar.MatchString(v.Name) {
			return "envVar " + v.Name, mask
		}
		return "envVar " + v.Name, v.Value
	case ir.Subagent:
		what = fmt.Sprintf("subagent %s (%s)", v.Name, v.PermissionMode)
		if len(v.Tools) == 0 {
			return what, "-"
		}
		return what, strings.Join(v.Tools, ", ")
	case ir.Skill:
		return "skill " + v.Name, "-"
	case ir.Plugin:
		if v.Version == "" {
			return "plugin " + v.Name, "-"
		}
		return "plugin " + v.Name, v.Version
	case ir.Sandbox:
		return sandboxGrant(v)
	case ir.StatusLine:
		return "statusLine", v.Command
	case ir.CredentialHelper:
		return "credentialHelper " + v.Variant, v.Command
	case ir.PermissionMode:
		return "permissionMode", v.Mode
	case ir.MCPApproval:
		return "mcpApproval " + v.Setting, v.Value
	case ir.BundledPayload:
		if v.ReferencedBy == "" {
			return bundledPayloadLine(v), "-"
		}
		return bundledPayloadLine(v), v.ReferencedBy
	case ir.InlineShell:
		what = "inlineShell " + v.Shell
		if v.Form == "fenced" {
			what += " (fenced)"
		}
		return what, v.Command
	case ir.PluginExecutable:
		return pluginExecutableLine(v), v.Path
	case ir.Provisioner:
		return provisionerLine(v), v.Command
	case ir.NetworkPolicy:
		return networkPolicyGrant(v)
	case ir.ToolPermission:
		return toolPermissionGrant(v)
	case ir.InstructionText:
		return "instructionText " + v.Setting, v.Text
	case ir.LSPServer:
		return "lspServer " + v.Name, v.Command
	default:
		return e.Kind(), "-"
	}
}

// Args returns the argument vector an entity declared, redacted, for a
// reporter whose format delimits each element structurally. Describe's what
// and value exclude it; CommandLine spells it for a single text column.
func Args(e ir.Entity) []string {
	switch v := e.(type) {
	case ir.MCPServer:
		return redactArgs(v.Command, v.Args)
	case ir.LSPServer:
		return redactArgs(v.Command, v.Args)
	default:
		return nil
	}
}

// CommandLine respells Describe's value when it is an MCP or LSP server's
// own command, quoting the command and each argument that needs it. Escape
// runs on the result, not on the elements first: quoting Escape's backslash
// spelling of a control byte would merge it with that literal text.
func CommandLine(e ir.Entity) (string, bool) {
	var command string
	var args []string
	switch v := e.(type) {
	case ir.MCPServer:
		if v.HeadersHelper != "" || v.ForwardedEnv != "" || v.Transport != ir.TransportStdio {
			return "", false
		}
		command, args = v.Command, v.Args
	case ir.LSPServer:
		command, args = v.Command, v.Args
	}
	if command == "" {
		return "", false
	}
	spelled := make([]string, 0, len(args)+1)
	spelled = append(spelled, quoteArg(Redact(command)))
	for _, a := range redactArgs(command, args) {
		spelled = append(spelled, quoteArg(a))
	}
	return strings.Join(spelled, " "), true
}

var argQuoter = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func quoteArg(a string) string {
	if a != "" && !strings.ContainsFunc(a, needsQuote) {
		return a
	}
	return `"` + argQuoter.Replace(a) + `"`
}

const (
	brailleBlank      = '\u2800'
	objectReplacement = '\ufffc'
)

func needsQuote(r rune) bool {
	return r == '"' || r == '\\' || r == brailleBlank || r == objectReplacement ||
		unicode.IsSpace(r) ||
		unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

// mcpEndpointFields resolves which of a server's two possible endpoints is
// transport-primary: an http server's own url, or a stdio server's own
// command, is the field its resolved transport actually reaches; the other
// is secondary and carries secondaryLabel when it needs one.
func mcpEndpointFields(v ir.MCPServer) (primary, secondary, secondaryLabel string) {
	primary, secondary, secondaryLabel = v.Command, v.URL, "url"
	if v.Transport != ir.TransportStdio {
		primary, secondary, secondaryLabel = v.URL, v.Command, "command"
	}
	return primary, secondary, secondaryLabel
}

// mcpEndpoints renders the single endpoint value carries: the primary one
// bare, or the secondary one labelled when it is all a stdio server
// declared — a bare url there would read as a command. A server declaring
// BOTH endpoints does not get a second value here; joining two
// attacker-authored strings into one unstructured channel lets a single
// forged field read as a genuine pair, so the second endpoint is disclosed
// in "what" instead, never here.
func mcpEndpoints(v ir.MCPServer) string {
	primary, secondary, secondaryLabel := mcpEndpointFields(v)
	switch {
	case primary != "":
		return primary
	case secondary != "":
		return secondaryLabel + "=" + secondary
	default:
		return ""
	}
}

func mcpDestinationLine(v ir.MCPServer, relation string) string {
	label, endpoint := "url", v.URL
	if v.Transport == ir.TransportStdio && (v.Command != "" || v.URL == "") {
		label, endpoint = "command", v.Command
	}
	return fmt.Sprintf("mcpServer %s (%s) %s %s=%q", v.Name, v.Transport, relation, label, endpoint)
}

func bundledPayloadLine(v ir.BundledPayload) string {
	what := "bundledPayload"
	switch {
	case v.Extension != "":
		what += " " + v.Extension
		if v.Executable == "true" {
			what += " +x"
		}
	case v.Executable == "true":
		what += " +x"
	}
	if v.Referenced == "true" {
		what += " (referenced)"
	}
	return what
}

func pluginExecutableLine(v ir.PluginExecutable) string {
	what := "pluginExecutable " + v.Name
	if v.Executable == "true" {
		what += " +x"
	}
	if v.Plugin != "" {
		what += " [" + v.Plugin + "]"
	}
	return what
}

// sandboxGrant labels which grant a value carries. The forms share one kind,
// so a bare label would leave the column reading the same for all of them.
func sandboxGrant(v ir.Sandbox) (what, value string) {
	switch {
	case v.Mode != "":
		return "sandbox mode", v.Mode
	case v.Access != "":
		return "sandbox " + v.Access, v.Path
	default:
		return "sandbox", v.SocketPath
	}
}

func networkPolicyGrant(v ir.NetworkPolicy) (what, value string) {
	if v.Default != "" {
		return "networkPolicy default", v.Default
	}
	return "networkPolicy pattern", v.Pattern
}

// toolPermissionGrant keeps an entry the adapter could not decompose in the
// value column, where the reader finds the argument of every other grant.
func toolPermissionGrant(v ir.ToolPermission) (what, value string) {
	if v.Argument == "" {
		return "permission", v.Tool
	}
	return "permission " + v.Tool, v.Argument
}

func provisionerLine(v ir.Provisioner) string {
	what := "provisioner " + v.Phase
	if v.Name != "" {
		what += " [" + v.Name + "]"
	}
	return what
}

func hookLine(h ir.Hook) string {
	what := "hook " + h.Event
	if h.Matcher != "" {
		what += " [" + h.Matcher + "]"
	}
	if autoStartEvents[h.Event] {
		what += " (fires without user action)"
	}
	return what
}
