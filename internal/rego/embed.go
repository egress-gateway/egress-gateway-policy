// Package rego contains the fixed workload baseline modules.
package rego

import "embed"

// Modules are private implementation resources consumed by bundle.Build.
//
//go:embed *.rego
var Modules embed.FS
