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

The library evaluates **normalized facts**, supplied by a trusted gateway adapter.
It does not parse HTTP/JSON/gRPC wire traffic, load Protobuf descriptors, publish
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

## Layout and consumers

| Path | Responsibility | Direct consumer |
| --- | --- | --- |
| `workload/` | Public rules, configuration validation, input/decision contracts | Controller and gateway |
| `bundle/` | Construct a workload OPA artifact from validated rules and fixed Rego | Controller and static Go callers |
| `internal/rego/` | Fixed workload evaluation and embedded resources | Bundle construction |
| `testdata/workload/` | Policy/input/expected-decision examples exercised with real OPA | Semantic tests and later adapter conformance work |
| `docs/workload-contract.md` | Serialization, normalization, compatibility and owner boundaries | Library consumers |

Controller owns the complete CRD and chooses direct type reuse or explicit mapping.
Gateway owns trustworthy forwarding targets, normalization, artifact loading and
enforcement. No Kubernetes or Envoy types are required by the public API.

## Development

Go 1.26 or newer is required; CI uses Go 1.26.7. OPA **1.20.2**, matching the
existing gateway dependency, is the tested runtime; bundles use **Rego v1**.
Compatibility with other runtime versions is not asserted.

```sh
make check
```

This checks formatting and runs `go vet`, `go test` and `go build`. Tests build
and load the actual bundle and evaluate the public decision query with OPA.
These are pure library checks; deployed protocol/streaming acceptance belongs to
later gateway integration. CI runs the same command. CodeRabbit automatically
reviews non-Draft PRs.
