# Workload policy contract

## Source, construction and ownership

The rule-semantic source is the controller Wiki's
[GatewayProfile CRD Design](https://github.com/egress-gateway/egress-gateway-controller/wiki/GatewayProfile-CRD-Design).
This library implements both workload rule families through public Go values,
`Policy.Validate()` and `bundle.Build(Policy) ([]byte, error)`. Build validates
before producing an artifact and performs no network or Kubernetes operations.

Policy owns rule semantics, normalized input/decision contracts, fixed Rego and
bundle construction. Controller owns the complete CRD, schema/versioning, bindings,
runtime capability admission, publication and status. It may embed these types or
map its own CRD types. Gateway owns protocol recognition, decoding, verified
forwarding targets, normalization, bundle loading and enforcement. Networking owns
isolation and platform prerequisites. The repository also owns future shared
egress-policy capabilities; this implementation contains only the workload baseline.

## Authoring and serialization

`workload.Policy` represents the `hostDenylist` and `requestConstraints` fields.
An empty `Policy{}` serializes to `{}` and imposes no baseline restrictions.
Optional nil slices mean omitted; supplied empty slices are invalid. Their Go
JSON tags use `omitzero` to preserve the difference. JSON `null` maps to absence,
not a third policy value. Pointer selectors distinguish an omitted field from a
supplied empty string; the latter is invalid. Ordinary Go JSON decoding is not a
strict CRD parser: ingestion owners must enforce their schema, including unknown
fields and duplicate JSON keys, before constructing the typed policy.

Validation rejects invalid enum values, duplicate set entries, duplicate constraint
names, incompatible scopes/decoders/selectors and the Wiki's field bounds. Errors
include a field/rule index. Main limits are 256 denylist entries, 128 constraints,
32 host matchers per constraint, 16 HTTP methods, 64 HTTP paths or gRPC methods,
32 requirements and 128 comparison values. String bounds count Unicode characters;
DNS/method/header/metadata syntax is ASCII as specified. All rule names are unique
DNS-label-style diagnostic identifiers, at most 63 characters.

Configured hosts are lowercase ASCII DNS names (including caller-converted IDNA),
without ports, trailing dots, wildcards or IP literals. `Exact` matches only that
name. `DomainSuffix` matches the name and subdomains separated by a DNS dot. IP
literal request targets are accepted as facts but these rules do not enforce CIDRs.
Any denylist match rejects, independently of rule order and constraint successes.

Each constraint has nonempty `match.hosts`, exactly one `match.http`/`match.grpc`,
and nonempty `require`. Dimensions combine with AND; alternatives in a list with
OR. Omitted HTTP methods/paths match all; omitted gRPC methods match all methods of
the exact service. HTTP methods are uppercase tokens; paths match exactly without
query/fragment. gRPC service/methods are case-sensitive identifiers. All applicable
constraints and every requirement must pass. An HTTP scope also applies to the
HTTP carrier of recognized gRPC, alongside applicable gRPC scopes.

A Payload requirement needs `decode`: HTTP uses JSON, gRPC uses Protobuf with an
HTTPS `descriptorSet.url` and `sha256:` plus 64 lowercase hex digits in `digest`.
The library checks reference syntax only. Gateway retrieves and verifies descriptor
bytes and checks service compatibility. A declared decoder must be ready even if
that constraint currently contains only attribute requirements. Without `decode`,
attribute-only rules require no body inspection. Header/Query require HTTP scope;
GRPCMetadata requires gRPC scope and a lowercase text key, excluding `-bin`.

| Operator | Required outcome |
| --- | --- |
| `In` | Selection exists; every value is a string in the comparison set. |
| `NotIn` | Selection exists; every value is a string outside the comparison set. |
| `Exists` | Selection is present and non-null. Comparison values are forbidden. |

Missing selections fail all operators. A present empty string is a value. Payload
`Exists` accepts empty objects/arrays; membership does not expand arrays, coerce
numbers, trim strings or fold case. A nonempty RFC 6901 pointer selects a nested
object value or explicit array index: `~1` means `/`, `~0` means `~`; `/` selects
an empty object key. Array indexes are canonical decimal (`0`, not `00`), while
numeric object keys remain strings. The empty root pointer is not supported by
the rule schema. Repeated attributes retain all values; every value must pass.

## Normalized input v1

`workload.Input` serializes the following fields. Input is produced by the trusted
gateway adapter, never accepted directly from the calling application.

| Field | Contract |
| --- | --- |
| `version` | Required literal `v1`. |
| `host` | Required canonical actual forwarding DNS name or IP literal; no port, bracket or trailing dot. Gateway resolves routing/authority consistency before evaluation. |
| `protocol` | `HTTP`, `GRPC`, `Other` or `Unknown`, from trusted protocol recognition. `Other` is positively outside HTTP/gRPC; `Unknown` means inspection cannot establish scope. |
| `http` | Optional object: required `method`, `path`; `headers`/`query` maps of names to nonempty string arrays. Valid for HTTP or gRPC carrier. |
| `grpc` | Optional object: required exact `service`, `method`; `metadata` map of text names to nonempty string arrays. Valid only for GRPC. |
| `payloads` | Optional array of decoded views; at most one per format/descriptor-digest pair. |

Header keys are lowercase HTTP tokens. Query names and values are case-sensitive
and already decoded once according to the upstream protocol. Do not double-decode,
trim values, split commas or collapse repeats. Metadata contains only lowercase text
keys; the adapter keeps binary metadata outside this map. Missing/null maps mean
unavailable inspection; `{}` means inspected with no attributes. Missing keys fail
selection in either case. A missing/null HTTP/gRPC object means scope inspection is
unavailable, not a known nonmatch. Malformed present objects/maps are invalid input.

Every payload view has `format` (`JSON` or `Protobuf`), `status`, and `value` (which
may be JSON null). Protobuf also requires `descriptorDigest`; JSON omits it or uses
an empty string. A Protobuf digest identifies the verified descriptor used to produce
that view, allowing overlapping constraints to require different descriptors.
`status` is `Ready`, `Unavailable`, `Invalid`, `Truncated` or `Unsupported`.
Only a complete `Ready` view with the requested format/digest satisfies `decode`.
Absent views, failed parsing, unavailable dependencies and incomplete decoding fail
an applicable constraint. Other statuses never make the supplied `value` usable.

JSON values are complete decoded JSON. Protobuf values use standard ProtoJSON
field names and presence/default mapping; `Exists` tests this representation and
does not prove explicit wire presence. The adapter owns framing, decompression,
size limits, descriptor compatibility and streaming/per-message enforcement.
Content-Type alone is not trusted protocol recognition and cannot disable gRPC
constraints. Normalized library tests do not establish wire-decoding conformance.

For valid facts, a positively determined host/protocol/method/path/service nonmatch
leaves the constraint inapplicable. At a matching host, `Unknown` protocol or a
missing necessary scope view denies the affected constraint. A known out-of-scope
request needs no decoder. Malformed input is rejected globally, including with an
empty baseline, since its asserted facts cannot be consumed under this contract.

## Decision and caller error handling

Evaluate **`data.egress_gateway.workload.decision`**. Its single expression is:

```json
{"version":"v1","allowed":false,"code":"deny","violations":["requestConstraints/model"]}
```

| Code | `allowed` | Meaning |
| --- | --- | --- |
| `pass` | true | All applicable workload checks passed (or none applied). |
| `deny` | false | At least one rule or required inspection failed. |
| `invalid_input` | false | Input version, shape or normalized fields are invalid. |
| `invalid_policy` | false | Required bundle data is absent, incompatible or structurally invalid. |

`violations` is a sorted array containing `hostDenylist` and/or
`requestConstraints/<name>` for `deny`, and is empty otherwise. Decisions never
return request values or credentials. Input and config guards check runtime shape;
full authoring bounds remain the responsibility of `Policy.Validate`/`bundle.Build`.
These guards do not authenticate modified bundle code: gateway must load a trusted,
verified artifact through its own loading boundary.

Consumers must first reject OPA errors and undefined/non-single expression results.
Encode that expression's value as JSON and call `workload.DecodeDecision`, which
rejects missing/null/unknown/duplicate fields, unknown versions/codes and inconsistent
allowed/code/violation combinations. Never treat a zero value, raw truthy JSON, or
failed evaluation as permission. The [executable example](../bundle/example_test.go)
shows this flow. Only successful decoding with `Allowed == true` reports baseline
pass; final egress authorization and network controls still apply.

## Artifact and compatibility

`bundle.Build` returns a standard gzipped OPA snapshot bundle, containing fixed
Rego v1 modules and data under `data.egress_gateway.workload.config`:

```json
{"version":"v1","policy":{"hostDenylist":[],"requestConstraints":[]}}
```

The builder canonicalizes omitted root lists to arrays only inside the artifact.
This valid empty baseline differs from missing `config`, `policy` or either array.
The manifest declares `rego_version: 1` and the sole owned root
`egress_gateway/workload`, covering both rules and data. Module files live under
`policy/`. Future egress policy must use a separate owned root; composition is not
implemented here. Contract version `v1` is unrelated to a controller generation,
bundle digest or rollout identifier. Unsupported contract versions fail closed.

OPA **1.20.2** is selected to match gateway and is exercised through actual bundle
reading, query preparation and evaluation. No custom builtins or policy service are
used. Evaluation performs no network I/O and produces the same decision for the same
rules and facts. Other OPA versions and byte-for-byte reproducible archive output
are not part of this compatibility claim. `make check` runs the pure Go/Rego gates;
publication, runtime activation and deployed traffic acceptance belong to consumers.
