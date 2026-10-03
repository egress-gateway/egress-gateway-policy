# Policy development

- Use English for repository content and GitHub communication.
- This repository owns shared workload-policy structures, semantic validation,
  normalized input and decision contracts, fixed baseline Rego, and workload
  bundle construction. Follow the controller Wiki's `workloadPolicy` semantics.
- The complete GatewayProfile CRD, ServiceAccount binding, publication and status
  reconciliation belong to controller. Protocol parsing, request normalization,
  artifact loading and traffic enforcement belong to gateway.
- Current work establishes the directory framework. Package documentation and
  examples describe intended contracts; they do not establish runtime support.
  Implement rule behavior and public API signatures in subsequent scoped work.
- Use a single Go module. Keep public contracts in `workload`, the public bundle
  construction boundary in `bundle`, and fixed Rego resources under
  `internal/rego`. Consumers must not import implementation packages.
- Policy types must remain independent of Kubernetes and Envoy types. Controller
  should reuse the policy structures for its CRD fields instead of maintaining a
  second manually translated rule model.
- Keep rule evaluation in Rego. Go validates policy configuration and assembles
  artifacts; it must not grow a second implementation of authorization decisions.
- Reuse upstream OPA capabilities. Add custom extensions only for a demonstrated
  rule requirement that existing capabilities cannot satisfy.
- Run `make check` for changes to Go or the check entrypoint. Add behavior tests
  alongside implemented semantics; an empty package check is not policy evidence.
- Preserve unrelated changes. Commit, push, PR state changes and publication
  follow the user's authorization for the specific action and repository.
