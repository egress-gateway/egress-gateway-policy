# Workload policy contract

## Source and status

The semantic source is the controller Wiki's
[GatewayProfile CRD Design](https://github.com/egress-gateway/egress-gateway-controller/wiki/GatewayProfile-CRD-Design).
That page defines a design specification and illustrative schema, not a released
API. This repository currently establishes directory and package boundaries only.

The shared structures will represent `spec.workloadPolicy` directly, preserving
its JSON field names and meanings. Controller owns the complete GatewayProfile
resource, Kubernetes validation schema, ServiceAccount binding and status.
Policy owns the rule model reused by that resource and by static Go callers.

## Public construction boundaries

The `workload` package will provide the policy structures and semantic validation.
Callers can construct rule values using those types. Focused helpers can be added
where they prevent demonstrated construction mistakes; a fluent builder is not
required by this contract.

The `bundle` package will combine validated policy data with the fixed baseline
Rego and construct a workload OPA artifact. The caller owns publication and
delivery. Bundle construction does not resolve ServiceAccounts, inspect live
traffic, fetch decoder dependencies or update Kubernetes resources.

The normalized input, decision shape, decision entry point, bundle data root and
compatibility version remain to be specified before executable integration. Keep
these choices aligned across controller, gateway and the fixed Rego; do not
publish placeholder signatures as a working API.

## Rule semantics to preserve

### Host denylist

- `Exact` matches the configured DNS name.
- `DomainSuffix` matches the name and its subdomains on DNS-label boundaries.
- Any matching entry rejects the request; list order has no priority semantics.
- The evaluated hostname is the normalized actual forwarding target supplied by
  gateway. Hostname restrictions do not claim IP/CIDR enforcement.

### Request constraints

Each constraint has `name`, `match`, optional `decode`, and nonempty `require`.
Match dimensions combine with AND; alternatives within a list combine with OR.
All matching constraints and every requirement within them must pass.

The Wiki defines HTTP and gRPC scopes; JSON and Protobuf decoder declarations;
and Payload, Header, Query and GRPCMetadata selectors. This scaffold implements
none of their runtime capabilities. A future supported subset must be explicit:
an unsupported required inspection cannot silently become a nonmatching rule.

| Operator | Required outcome |
| --- | --- |
| `In` | The selection exists and every selected value is a string in the comparison set. |
| `NotIn` | The selection exists and every selected value is a string outside the comparison set. |
| `Exists` | The selection is present and non-null; it need not be a string or nonempty. |

Missing selections fail all operators, including `NotIn`. Payload membership
selects one string value; arrays are not implicitly expanded. Repeated header,
query and metadata values must retain their meaning and all satisfy membership
requirements. Decoder errors, incomplete required input and evaluation errors
are not successful checks.

An empty `workloadPolicy` adds no baseline restrictions. A positively unmatched
constraint leaves the request unaffected by that constraint. Neither case
overrides applicable network controls or the gateway's independent authorization.

## Owner boundaries

| Owner | Responsibility |
| --- | --- |
| Policy | Shared rule structures, semantics, validation, normalized-input/decision contracts, fixed Rego and workload bundle construction |
| Gateway | Verified identity and forwarding target, protocol recognition and decoding, normalized facts, artifact loading and decision enforcement |
| Controller | CRD and bindings, runtime capability acceptance, publication, configuration projection and status reconciliation |
| Networking | Supported network isolation and platform prerequisites |

The workload bundle contains baseline checks and their data. Credentials, request
mutation instructions and external egress policy implementation are outside the
current repository task.

## Implementation sequence

Start with an executable host-denylist slice covering shared types, validation,
fixed Rego, bundle construction and semantic tests. Then add request constraints
in explicitly supported slices while preserving the Wiki's composition and error
semantics. Real protocol-adapter acceptance remains separate from pure policy
evaluation and bundle tests.
