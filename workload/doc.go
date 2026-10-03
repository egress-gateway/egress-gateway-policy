// Package workload defines workload-policy rules, configuration validation and
// versioned normalized input and decision contracts independent of Kubernetes
// and Envoy. Controller maps or embeds Policy; gateway produces Input, evaluates
// a bundle and consumes Decision using DecodeDecision. A pass covers the workload
// baseline only. See docs/workload-contract.md for normalization and error handling.
package workload
