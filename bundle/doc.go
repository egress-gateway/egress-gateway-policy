// Package bundle is reserved for constructing workload OPA bundles from shared
// policy data and the project's fixed baseline Rego implementation.
//
// Construction will use explicit inputs without network access or publication.
// Controller owns publication and desired configuration; gateway owns loading
// and enforcement. This scaffold does not yet expose a construction function.
package bundle
