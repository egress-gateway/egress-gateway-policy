# Shared workload examples

`http-model.json` contains a public serialized `policy` and named `cases`, each
with normalized `input` and a complete `expected` decision. The bundle tests build
that policy, load the generated artifact in real OPA and compare all result fields.
Gateway adapter tests can reuse these cases; normalized fixtures alone do not prove
wire parsing. Additional selector, matching, inspection and error combinations are
table-driven tests in `bundle/`; authoring validation tests live in `workload/`.
