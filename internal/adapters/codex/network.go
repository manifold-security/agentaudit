package codex

import (
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const (
	featuresKey         = "features"
	networkProxyKey     = "network_proxy"
	localBindingKey     = "allow_local_binding"
	allUnixSocketsKey   = "dangerously_allow_all_unix_sockets"
	nonLoopbackProxyKey = "dangerously_allow_non_loopback_proxy"
)

var networkGuardKeys = []string{
	localBindingKey,
	allUnixSocketsKey,
	nonLoopbackProxyKey,
}

func networkEntities(doc map[string]any) ([]ir.Entity, []adapter.Warning) {
	features, warnings := tableAt(configFileName, featuresKey, doc[featuresKey])

	proxyKey := featuresKey + "." + networkProxyKey
	proxy, proxyWarnings := tableAt(configFileName, proxyKey, features[networkProxyKey])
	warnings = append(warnings, proxyWarnings...)

	entities, tableWarnings := entitiesFromNetworkProxy(proxyKey, proxy)
	warnings = append(warnings, tableWarnings...)

	return entities, warnings
}

func entitiesFromNetworkProxy(key string, proxy map[string]any) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning

	domains, domainWarnings := tableAt(configFileName, key+"."+domainsKey, proxy[domainsKey])
	warnings = append(warnings, domainWarnings...)
	domainEntities, domainVerdictWarnings := entitiesFromDomains(key+"."+domainsKey, domains)
	entities = append(entities, domainEntities...)
	warnings = append(warnings, domainVerdictWarnings...)

	sockets, socketWarnings := tableAt(configFileName, key+"."+unixSocketsKey, proxy[unixSocketsKey])
	warnings = append(warnings, socketWarnings...)
	socketEntities, socketVerdictWarnings := entitiesFromUnixSockets(key+"."+unixSocketsKey, sockets)
	entities = append(entities, socketEntities...)
	warnings = append(warnings, socketVerdictWarnings...)

	guards, guardWarnings := entitiesFromNetworkGuards(key, proxy)
	entities = append(entities, guards...)
	warnings = append(warnings, guardWarnings...)

	return entities, warnings
}

func entitiesFromNetworkGuards(key string, table map[string]any) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, name := range networkGuardKeys {
		guardKey := key + "." + name
		lifted, present, formWarnings := boolAt(configFileName, guardKey, table[name])
		warnings = append(warnings, formWarnings...)
		if !present || !lifted {
			continue
		}
		entities = append(entities, ir.NetworkPolicy{
			Default:  name,
			Location: ir.Location{File: configFileName, Key: guardKey},
		})
	}
	return entities, warnings
}
