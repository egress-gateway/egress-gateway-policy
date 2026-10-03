# Policy development

- Use English for repository content and GitHub communication.
- This repository is the shared OPA policy layer for workload and future egress
  capabilities. Its implemented workload baseline owns public rule structures,
  validation, normalized input/decision contracts, fixed Rego, bundle construction
  and the public OPA extension for policy-related inspection and strict decisions.
  Follow the controller Wiki's `workloadPolicy` semantics.
- The complete GatewayProfile CRD, ServiceAccount binding, publication and status
  reconciliation belong to controller. Policy owns request normalization, payload
  decoding and descriptor verification. Upstream OPA owns bundle loading, native
  activation and compilation. Gateway owns trusted target/peer facts, TLS, process
  lifecycle and traffic enforcement.
- Workload library tests establish pure policy semantics, not wire decoding or
  deployed gateway/controller acceptance. Extension tests use a real OPA runtime
  and the official Envoy authorization plugin; they do not prove live mesh
  authentication or network isolation. Keep these evidence layers distinct.
- Use a single Go module. Keep public contracts in `workload`, the public bundle
  construction boundary in `bundle`, and fixed Rego resources under
  `internal/rego`, and the supported OPA integration in `extension`. Consumers
  must not import implementation packages.
- Public authoring/input/decision types must remain independent of Kubernetes
  and Envoy types. The extension may consume Envoy authorization facts. Controller
  owns its CRD model and chooses direct reuse or explicit mapping to policy types.
- Keep rule evaluation in Rego. Go validates policy configuration and assembles
  artifacts; it must not grow a second implementation of authorization decisions.
- Reuse upstream OPA capabilities. Add custom extensions only for a demonstrated
  rule requirement that existing capabilities cannot satisfy.
- Run `make check` for changes to Go or the check entrypoint. Add behavior tests
  alongside implemented semantics; an empty package check is not policy evidence.
- Preserve unrelated changes. Commit, push, PR state changes and publication
  follow the user's authorization for the specific action and repository.
