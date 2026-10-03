// Package workload is reserved for shared workload-policy structures, semantic
// validation, normalized request inputs, and baseline decisions.
//
// Controller will reuse the policy structures in GatewayProfile.spec.workloadPolicy.
// Gateway will produce normalized inputs and consume the decision contract. These
// contracts remain independent of Kubernetes resources and Envoy transport types.
//
// This scaffold documents ownership only; no policy types or functions are
// implemented yet. See docs/workload-contract.md for the intended semantics.
package workload
