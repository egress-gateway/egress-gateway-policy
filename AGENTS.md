# Policy development

- Use English for repository content and GitHub communication.
- This repository is the shared OPA policy layer for workload and future egress
  capabilities. Its implemented workload baseline owns public rule structures,
  validation, normalized input/decision contracts, fixed Rego and bundle construction.
  Follow the controller Wiki's `workloadPolicy` semantics.
- The complete GatewayProfile CRD, ServiceAccount binding, publication and status
  reconciliation belong to controller. Protocol parsing, request normalization,
  artifact loading and traffic enforcement belong to gateway.
- Workload library tests establish pure policy semantics, not wire decoding or
  deployed gateway/controller acceptance. Keep these evidence layers distinct.
- Use a single Go module. Keep public contracts in `workload`, the public bundle
  construction boundary in `bundle`, and fixed Rego resources under
  `internal/rego`. Consumers must not import implementation packages.
- Policy types must remain independent of Kubernetes and Envoy types. Controller
  owns its CRD model and chooses direct reuse or explicit mapping to policy types.
- Keep rule evaluation in Rego. Go validates policy configuration and assembles
  artifacts; it must not grow a second implementation of authorization decisions.
- Reuse upstream OPA capabilities. Add custom extensions only for a demonstrated
  rule requirement that existing capabilities cannot satisfy.
- Run `make check` for changes to Go or the check entrypoint. Add behavior tests
  alongside implemented semantics; an empty package check is not policy evidence.
- Preserve unrelated changes. Commit, push, PR state changes and publication
  follow the user's authorization for the specific action and repository.
