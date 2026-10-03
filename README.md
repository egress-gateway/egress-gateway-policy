# Egress Gateway Policy

Shared workload-policy contracts and baseline policy implementation for Egress
Gateway. The design follows the controller's
[GatewayProfile CRD specification](https://github.com/egress-gateway/egress-gateway-controller/wiki/GatewayProfile-CRD-Design).

## Status

This repository currently contains a directory framework, package documentation,
a design example, and basic Go checks. Public policy types, construction APIs,
semantic validation, executable Rego and bundle generation are not implemented.
It does not yet enforce a policy or complete V01-04 acceptance.

The initial scope is the structured `workloadPolicy` baseline:

- `hostDenylist`: exact and domain-suffix destination restrictions.
- `requestConstraints`: request matching, optional decoding requirements, and
  conjunctive `In`, `NotIn` and `Exists` requirements.

The current task does not implement the external, gateway-only egress bundle.
The same workload baseline is intended to run at both the workload proxy and
egress gateway; its repository ownership is independent of that later integration.

## Layout and consumers

| Path | Responsibility | Direct consumer |
| --- | --- | --- |
| `workload/` | Shared policy structures, semantic validation, normalized request input and baseline decision contracts | Controller and gateway |
| `bundle/` | Construct a workload OPA bundle from policy data and fixed Rego | Controller and static integration callers |
| `internal/rego/` | Fixed baseline rule implementation and embedded resources | The bundle package |
| `testdata/workload/` | Shared policy/input/expected-decision examples for semantic tests | Policy tests and later adapter conformance work |
| `examples/` | Human-readable workload policy examples | Policy authors and Go consumers |
| `docs/workload-contract.md` | Contract source, semantic boundaries and planned API responsibilities | Implementers and consumers |

Controller owns the complete Kubernetes CRD and reuses the shared policy fields.
Gateway supplies trustworthy normalized request facts and enforces decisions.
The intended flow is:

```text
GatewayProfile.spec.workloadPolicy or a static Go caller
  -> shared workload structures and validation
  -> bundle construction with fixed Rego
  -> consumer-owned publication/loading
  -> OPA evaluation using gateway-normalized input
  -> gateway enforcement
```

See the [workload contract](docs/workload-contract.md) and
[design example](examples/workload-policy.yaml). The example is not a complete
GatewayProfile resource or an executable bundle.

## Development

Use Go 1.26 or newer; CI uses Go 1.26.7. This scaffold has no third-party Go
dependencies. Runtime integration must select an OPA version compatible with
the consuming gateway when executable policy work begins.

```sh
make check
```

This runs formatting checks, `go vet`, `go test` and `go build`. At this stage,
the Go packages contain documentation only and there are no behavior tests.
CI runs the same command. CodeRabbit configuration matches the gateway
repository: automatic incremental reviews are enabled for non-Draft PRs.
