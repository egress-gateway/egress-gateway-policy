# Egress Gateway Policy

The shared OPA policy layer for Egress Gateway's workload and future egress
capabilities. The implemented workload baseline follows the controller's
[GatewayProfile CRD specification](https://github.com/egress-gateway/egress-gateway-controller/wiki/GatewayProfile-CRD-Design).

## Supported workload rules

- `hostDenylist`: exact and DNS-label-boundary suffix destination matching.
- `requestConstraints`: HTTP and gRPC scopes, JSON and ProtoJSON payload facts,
  payload/header/query/text-metadata selection, and `In`, `NotIn`, `Exists`.
- Conjunction across matching constraints, inspection failure handling, semantic
  validation and standard OPA bundle construction with fixed Rego and rule data.

The core library evaluates **normalized facts**. The Policy-owned OPA extension
normalizes trusted Envoy authorization facts, performs strict JSON and unary gRPC
inspection, verifies staged descriptors and adapts decisions. It does not publish
bundles or enforce network traffic. The external egress bundle and its composition
are future work in this repository. A workload pass is not final egress permission.

## Use

```go
policy := workload.Policy{
    HostDenylist: []workload.HostMatcher{
        {Type: workload.DomainSuffix, Value: "restricted.example"},
    },
}
archive, err := bundle.Build(policy) // validates; no external I/O
```

Load the returned snapshot bundle with OPA and evaluate
`data.egress_gateway.workload.decision` with a `workload.Input`. Treat OPA errors,
undefined/multiple results and invalid decisions as failure. Pass the single
expression's JSON value to `workload.DecodeDecision` before using `Allowed`.
The executable [Go example](bundle/example_test.go) demonstrates this complete
flow; [shared JSON cases](testdata/workload/http-model.json) demonstrate HTTP
payload rules and outcomes. The [YAML example](examples/workload-policy.yaml)
contains policy fields only, not a complete GatewayProfile resource.

## Native OPA integration

Publish `bundle.BuildExecution(policy, revision)` for the supported extension
path. The host calls `extension.Register()` before creating OPA and configures
`plugins.egress_gateway_workload`; the official Envoy plugin uses
`extension.DecisionPath` with `skip-request-body-parse: true`. Standard OPA bundle
files or bundle services load the complete execution artifact. The host does not
read the policy DSL, prepare descriptors or generate bridge Rego.

See [extension integration and migration](docs/opa-extension.md) for configuration,
readiness, update behavior and the staged adoption contract.

## Layout and consumers

| Path | Responsibility | Direct consumer |
| --- | --- | --- |
| `workload/` | Public rules, configuration validation, input/decision contracts | Controller and gateway |
| `bundle/` | Construct a workload OPA artifact from validated rules and fixed Rego | Controller and static Go callers |
| `extension/` | Native OPA registration, policy inspection, descriptor readiness and strict authorization bridge | Gateway OPA host |
| `internal/rego/` | Fixed workload evaluation and embedded resources | Bundle construction |
| `testdata/workload/` | Policy/input/expected-decision examples exercised with real OPA | Semantic tests and later adapter conformance work |
| `docs/workload-contract.md` | Serialization, normalization, compatibility and owner boundaries | Library consumers |

Controller owns the complete CRD and chooses direct type reuse or explicit mapping.
Gateway owns trustworthy forwarding targets and peer facts, TLS, process lifecycle
and enforcement. Upstream OPA owns bundle transport, compilation and activation.
The authoring/input/decision API remains independent of Kubernetes and Envoy.

## Development

Go 1.26 or newer is required; CI uses Go 1.26.7. OPA **1.20.2**, matching the
existing gateway dependency, is the tested runtime; bundles use **Rego v1**.
Compatibility with other runtime versions is not asserted.

```sh
make check
```

This checks formatting and runs `go vet`, `go test` and `go build`. Tests build
and load the actual bundle and evaluate the public decision query with OPA.
Core tests establish pure policy semantics. Extension tests exercise actual
OPA and the official Envoy authorization service, native bundle updates and
recovery. Deployed traffic, mesh identity and isolation acceptance belongs to
Gateway integration. CI runs the same command. CodeRabbit automatically
reviews non-Draft PRs.
