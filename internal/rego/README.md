# Fixed workload baseline

The private embedding package supplies Rego v1 modules to `bundle.Build`:

- `hosts.rego`: exact/suffix matching and denylist checks.
- `constraints.rego`: scope composition, required inspection and selection/operators.
- `validation.rego`: structural bundle-data and normalized-input guards.
- `workload.rego`: versioned decision at `data.egress_gateway.workload.decision`.

Go validates rule authoring and assembles artifacts. Authorization evaluation lives
here. Tests under `bundle/` exercise these modules through the actual public builder
and OPA, including error paths. The Policy extension owns policy-related parsing
and decoding, and `bundle.BuildExecution` adds the authorization bridge. Gateway
owns enforcement; publication and CRD reconciliation belong to controller.
