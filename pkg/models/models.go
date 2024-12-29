package models

type FirewallMethod uint16

const (
	LogOnly   FirewallMethod = 0
	AllowList FirewallMethod = 1
	BlockList FirewallMethod = 2
)
