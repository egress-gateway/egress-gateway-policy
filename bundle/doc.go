// Package bundle constructs standard workload OPA snapshot bundles from validated
// workload.Policy values and fixed Rego v1. Build performs no external I/O.
// Controller owns publication; gateway owns trusted loading and enforcement.
package bundle
