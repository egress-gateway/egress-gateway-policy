# Workload semantic cases

This directory is reserved for shared policy, normalized-input and expected-result
fixtures as rule implementations are added. No behavior cases exist yet.

Cases should cover observable rule behavior: DNS-label suffix boundaries,
conjunction across matching constraints, missing values under every operator,
repeated attribute values, type mismatches, and unavailable inspection inputs.

Exercise the real Rego and generated bundle. Go configuration-validation tests
belong next to the validation implementation. Gateway adapter tests can reuse
semantic examples without treating a normalized fixture as proof of wire parsing.

The fixture format will be selected with the first executable rules; this scaffold
does not introduce a separate test runner or validation framework.
