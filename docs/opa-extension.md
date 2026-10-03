# OPA extension integration

## Supported host boundary

Use OPA 1.20.2 and the official OPA Envoy plugin 1.20.2-envoy. The host registers
`extension.Register()` and the official Envoy plugin factory before constructing
OPA. Supply ordinary OPA configuration, for example:

```yaml
plugins:
  egress_gateway_workload:
    role: egress
    allowedPeers: ["spiffe://mesh.example/ns/app/sa/app"]
    descriptors:
      - url: https://artifacts.example/api.pb
        digest: sha256:<64 lowercase hex digits>
        path: /etc/policy/api.pb
  envoy_ext_authz_grpc:
    addr: unix:///run/gateway/auth.sock
    path: egress_gateway/workload/authorization/allow
    skip-request-body-parse: true
services:
  policies:
    url: https://bundles.example
bundles:
  workload:
    service: policies
    resource: workload.tar.gz
```

For a workload-side host, set `role: workload`; peer bindings are required for
`egress`. `allowedPeers` authorizes the verified Envoy source principal separately
from the workload decision. Application headers cannot provide that principal or
prior authorization. Gateway remains responsible for authenticating the mesh peer
and supplying the actual enforced forwarding destination. Configure Envoy to pass
lossless `HeaderMap`, raw request bytes, and the 64 KiB complete-body bound; legacy
combined header maps cannot prove repeated attribute values.

Publish `bundle.BuildExecution(policy, revision)`. The returned standard snapshot
contains all rule data, fixed Rego and the Policy-owned authorization bridge.
Alternatively, load this artifact as an ordinary OPA bundle file. OPA performs
transport, compilation, storage and activation. The Gateway host does not inspect
DSL fields, decode policy payloads, inspect descriptor definitions or generate
Rego. No separate authorization service is introduced.

## Inspection and updates

The extension reads explicitly staged descriptors while OPA validates plugin
configuration, verifying SHA-256 byte identity and complete imports. Each policy
also requires its declared services and methods to exist. URLs identify artifacts;
there is no descriptor HTTP retrieval. No request reads descriptor files or other
artifacts. Changing staged files after configuration does not change active bytes;
provide required descriptors in trusted configuration before adopting policy that
uses them. Configuration errors fail runtime initialization.

The bridge passes the current OPA transaction's policy data into inspection. A
private bounded cache retains one prepared policy and its immutable decoder views;
concurrent old/new evaluations use the view corresponding to their own policy
value. Required inspection follows bundle changes without capturing the startup
DSL. A missing or incompatible dependency makes the active policy fail closed and
marks the extension not ready, including when a previous policy was usable.
Restoring a compatible policy restores readiness. Strict JSON, repeated values,
ProtoJSON, per-digest views, complete unary framing and the 64 KiB limit remain the
V01-05 contract. Compressed or streaming gRPC is unsupported.

Before a usable execution bundle exists, the extension is not ready and no request
is authorized. A valid empty policy is usable and still requires egress admission.
Native download/load/compile failures retain the last activated bundle according
to OPA's behavior. The extension observes successful store commits and does not
replace OPA's activation transaction, coordinate activation in Gateway, or add a
custom status endpoint. `GET /health?plugins&bundles`, native plugin status and
bundle status provide diagnostics. Native `active_revision` describes activation;
an incompatible inspection dependency remains not ready and is not a newly usable
policy. Host liveness must not restart OPA solely because a recoverable bundle or
inspection-readiness condition fails; readiness should expose that condition while
OPA's native update loop can recover.

## Compatibility and migration

`bundle.Build` and `workload.DecisionQuery` remain unchanged for existing consumers
of normalized `workload.Input`. They do not require extension registration.
`BuildExecution` adds `extensionVersion: v1` to bundle configuration and the
`egress_gateway/workload/authorization/allow` entry point; it requires registration
of this extension. The normalized input and decision versions remain `v1`.

For staged Gateway adoption, pin the immutable Policy revision introducing this
API, switch publication/fixtures to `BuildExecution`, register/configure the
extension and point Envoy authorization at `extension.DecisionPath`. Remove the
Gateway-owned DSL inspection, decoder, descriptor preparation and bridge artifact
path together. Existing core-only artifacts are deliberately not treated as ready
extension artifacts. This package does not rewrite another repository or publish
artifacts on its behalf.

Core tests prove normalized semantics. Extension tests run real OPA and the
upstream Envoy authorization service, including native updates with changed
inspection requirements, unavailable dependencies and recovery. They do not prove
live mesh identity, network isolation, image behavior or real-traffic
update-to-effective duration; those are Gateway's deployment acceptance.
