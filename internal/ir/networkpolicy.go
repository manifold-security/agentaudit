package ir

// NetworkPolicy is one egress grant a sandbox network policy makes.
type NetworkPolicy struct {
	// Default is the action traffic falls back to when no pattern matches
	// it, verbatim.
	Default string
	// Pattern is one entry of a policy list: an exact host, a wildcard
	// domain, or a CIDR block.
	Pattern  string
	Location Location
}

func (NetworkPolicy) Kind() string { return KindNetworkPolicy }

func (n NetworkPolicy) Identity() string {
	return identity(KindNetworkPolicy, n.Default, n.Pattern)
}
