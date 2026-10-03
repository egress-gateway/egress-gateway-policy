// Package workload defines workload-policy rules, configuration validation and
// versioned normalized input and decision contracts independent of Kubernetes
// and Envoy. Controller maps or embeds Policy; the Policy OPA extension produces
// Input and consumes Decision using DecodeDecision. Existing normalized-input
// consumers can continue evaluating the core bundle directly. A pass covers the workload
// baseline only. See docs/workload-contract.md for normalization and error handling.
package workload
