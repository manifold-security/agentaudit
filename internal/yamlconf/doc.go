// Package yamlconf parses a YAML configuration document into its node tree
// and checks its mappings before anything decodes them: yaml.v3's Decode
// compares a mapping's keys pairwise and formats an error per duplicate pair.
package yamlconf
