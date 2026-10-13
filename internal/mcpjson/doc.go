// Package mcpjson decodes the mcpServers object that several agents share.
//
// Transport resolution stays with the caller: the key spellings and aliases
// an agent honours are vendor facts about that agent, and reading one agent's
// alias out of another's file would report a transport its vendor never
// promised to read.
package mcpjson
