# Fixed workload baseline

This directory will contain the shared baseline Rego implementation and its Go
embedding boundary. Planned modules cover host matching, request constraints,
and the combined baseline decision.

The bundle package will consume these resources through a private Go package.
No executable Rego or embedding code exists in this scaffold. Add each module
with tests for its actual semantics instead of placeholder allow decisions.

Rule evaluation belongs here. Request parsing and decoding remain in gateway;
policy publication and Kubernetes reconciliation remain in controller.
