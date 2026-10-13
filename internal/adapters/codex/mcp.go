package codex

import (
	"errors"
	"strconv"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/tomlconf"
)

const (
	mcpServersKey        = "mcp_servers"
	urlKey               = "url"
	argsKey              = "args"
	envKey               = "env"
	envVarsKey           = "env_vars"
	bearerTokenEnvVarKey = "bearer_token_env_var"
	envHTTPHeadersKey    = "env_http_headers"
	headersHelperKey     = "http_headers_helper"
	nameKey              = "name"
	sourceKey            = "source"
)

func mcpEntities(doc map[string]any) ([]ir.Entity, []adapter.Warning) {
	servers, warnings := tableAt(configFileName, mcpServersKey, doc[mcpServersKey])

	var entities []ir.Entity
	for _, entry := range tableEntries(mcpServersKey, servers) {
		table, tableWarnings := tableAt(configFileName, entry.key, entry.value)
		warnings = append(warnings, tableWarnings...)
		if table == nil {
			continue
		}
		found, serverWarnings := mcpServerEntities(entry.name, entry.key, table)
		entities = append(entities, found...)
		warnings = append(warnings, serverWarnings...)
	}
	return entities, warnings
}

func mcpServerEntities(name, key string, table map[string]any) ([]ir.Entity, []adapter.Warning) {
	enabled, present, warnings := boolAt(configFileName, key+"."+enabledKey, table[enabledKey])
	if present && !enabled {
		return nil, nil
	}

	command, commandWarnings := stringAt(configFileName, key+"."+commandKey, table[commandKey])
	warnings = append(warnings, commandWarnings...)
	url, urlWarnings := stringAt(configFileName, key+"."+urlKey, table[urlKey])
	warnings = append(warnings, urlWarnings...)

	server := ir.MCPServer{Name: name, Command: command, URL: url}
	switch {
	case command != "":
		server.Transport = ir.TransportStdio
	case url != "":
		server.Transport = ir.TransportHTTP
	case len(commandWarnings) != 0:
		server.Transport = ir.TransportStdio
	case len(urlWarnings) != 0:
		server.Transport = ir.TransportHTTP
	default:
		warnings = append(warnings, missingEndpoint(key, table)...)
	}

	stdio := ir.MCPServer{Name: name, Transport: ir.TransportStdio, Command: command, URL: url}
	args, env, forwarded, stdioWarnings := stdioFields(stdio, key, table)
	warnings = append(warnings, stdioWarnings...)

	http := ir.MCPServer{Name: name, Transport: ir.TransportHTTP, Command: command, URL: url}
	httpForwarded, httpWarnings := httpFields(http, key, table)
	forwarded = append(forwarded, httpForwarded...)
	warnings = append(warnings, httpWarnings...)

	if server.Transport == "" {
		return forwarded, warnings
	}
	if server.Transport == ir.TransportStdio {
		server.Args, server.Env = args, env
	}
	server.Location = ir.Location{File: configFileName, Key: key}
	return append([]ir.Entity{server}, forwarded...), warnings
}

func missingEndpoint(key string, table map[string]any) []adapter.Warning {
	var warnings []adapter.Warning
	for _, endpoint := range []string{commandKey, urlKey} {
		if _, declared := table[endpoint]; declared {
			warnings = append(warnings, adapter.Warning{
				File: configFileName,
				Err:  errors.New(key + "." + endpoint + ": expected a non-empty string, found an empty string"),
			})
		}
	}
	if len(warnings) == 0 {
		warnings = append(warnings, adapter.Warning{
			File: configFileName,
			Err:  errors.New(key + ": expected a command or a url, found neither"),
		})
	}
	return warnings
}

func stdioFields(server ir.MCPServer, key string, table map[string]any) ([]string, map[string]string, []ir.Entity, []adapter.Warning) {
	elements, warnings := stringListAt(configFileName, key+"."+argsKey, table[argsKey], "strings", "a string")
	var args []string
	for _, e := range elements {
		args = append(args, e.value)
	}

	env, envWarnings := stringTableAt(key+"."+envKey, table[envKey])
	warnings = append(warnings, envWarnings...)
	var envMap map[string]string
	for _, e := range env {
		if envMap == nil {
			envMap = map[string]string{}
		}
		envMap[e.name] = e.value
	}

	vars, varWarnings := elementsOf(key+"."+envVarsKey, table[envVarsKey])
	warnings = append(warnings, varWarnings...)
	var forwarded []ir.Entity
	for _, v := range vars {
		name, local, varWarnings := localVariable(v.key, v.value)
		warnings = append(warnings, varWarnings...)
		if local {
			forwarded = append(forwarded, forwardedTo(server, name, v.key))
		}
	}
	return args, envMap, forwarded, warnings
}

func httpFields(server ir.MCPServer, key string, table map[string]any) ([]ir.Entity, []adapter.Warning) {
	var forwarded []ir.Entity

	bearerKey := key + "." + bearerTokenEnvVarKey
	bearer, warnings := stringAt(configFileName, bearerKey, table[bearerTokenEnvVarKey])
	if bearer != "" {
		forwarded = append(forwarded, forwardedTo(server, bearer, bearerKey))
	}

	headers, headerWarnings := stringTableAt(key+"."+envHTTPHeadersKey, table[envHTTPHeadersKey])
	warnings = append(warnings, headerWarnings...)
	for _, h := range headers {
		if h.value != "" {
			forwarded = append(forwarded, forwardedTo(server, h.value, h.key))
		}
	}

	helperKey := key + "." + headersHelperKey
	helper, helperWarnings := stringAt(configFileName, helperKey, table[headersHelperKey])
	warnings = append(warnings, helperWarnings...)
	if helper != "" {
		h := server
		h.HeadersHelper = helper
		h.Location = ir.Location{File: configFileName, Key: helperKey}
		forwarded = append(forwarded, h)
	}
	return forwarded, warnings
}

func forwardedTo(server ir.MCPServer, variable, key string) ir.MCPServer {
	server.ForwardedEnv = variable
	server.Location = ir.Location{File: configFileName, Key: key}
	return server
}

func localVariable(key string, v any) (string, bool, []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormString:
		return v.(string), v.(string) != "", nil
	case tomlconf.FormTable:
	default:
		return "", false, []adapter.Warning{warnAt(configFileName, key, "a variable name or a table", f)}
	}

	entry := v.(map[string]any)
	name, warnings := requiredStringAt(configFileName, key+"."+nameKey, entry[nameKey])
	switch source := entry[sourceKey]; source {
	case nil, "local":
	case "remote":
		return "", false, warnings
	default:
		found := tomlconf.FormName(tomlconf.FormOf(source))
		if s, ok := source.(string); ok {
			found = strconv.Quote(s)
		}
		warnings = append(warnings, adapter.Warning{
			File: configFileName,
			Err:  errors.New(key + "." + sourceKey + ": expected one of local or remote, found " + found),
		})
	}
	return name, name != "", warnings
}

type stringEntry struct {
	key   string
	name  string
	value string
}

func stringTableAt(key string, v any) ([]stringEntry, []adapter.Warning) {
	table, warnings := tableAt(configFileName, key, v)
	var entries []stringEntry
	for _, e := range tableEntries(key, table) {
		value, valueWarnings := stringAt(configFileName, e.key, e.value)
		warnings = append(warnings, valueWarnings...)
		if len(valueWarnings) == 0 {
			entries = append(entries, stringEntry{key: e.key, name: e.name, value: value})
		}
	}
	return entries, warnings
}

type arrayElement struct {
	key   string
	value any
}

func elementsOf(key string, v any) ([]arrayElement, []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return nil, nil
	case tomlconf.FormArray:
	default:
		return nil, []adapter.Warning{warnAt(configFileName, key, "an array", f)}
	}
	var elements []arrayElement
	for i, raw := range v.([]any) {
		elements = append(elements, arrayElement{key: key + "[" + strconv.Itoa(i) + "]", value: raw})
	}
	return elements, nil
}
