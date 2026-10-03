package bundle_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
)

func evaluator(t *testing.T, policy workload.Policy) func(any) workload.Decision {
	t.Helper()
	archive, err := bundle.Build(policy)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := opabundle.NewReader(bytes.NewReader(archive)).Read()
	if err != nil {
		t.Fatal(err)
	}
	return bundleEvaluator(t, loaded)
}

func bundleEvaluator(t *testing.T, loaded opabundle.Bundle) func(any) workload.Decision {
	t.Helper()
	query, err := rego.New(rego.Query(workload.DecisionQuery), rego.ParsedBundle("workload", &loaded), rego.StrictBuiltinErrors(true)).PrepareForEval(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return func(input any) workload.Decision {
		t.Helper()
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var wire any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		results, err := query.Eval(t.Context(), rego.EvalInput(wire))
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 || len(results[0].Expressions) != 1 {
			t.Fatalf("undefined/ambiguous decision: %+v", results)
		}
		encoded, err = json.Marshal(results[0].Expressions[0].Value)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := workload.DecodeDecision(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return decision
	}
}

func TestHostBundle(t *testing.T) {
	eval := evaluator(t, workload.Policy{HostDenylist: []workload.HostMatcher{
		{Type: workload.Exact, Value: "exact.example"},
		{Type: workload.DomainSuffix, Value: "blocked.example"},
	}})
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"exact.example", false}, {"sub.exact.example", true},
		{"blocked.example", false}, {"sub.blocked.example", false},
		{"notblocked.example", true}, {"blocked.example.other", true},
		{"192.0.2.1", true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			d := eval(workload.Input{Version: workload.Version, Host: tc.host, Protocol: workload.Other})
			if d.Allowed != tc.allowed {
				t.Fatalf("decision = %+v", d)
			}
		})
	}
}

func TestInvalidPolicyDoesNotProduceBundle(t *testing.T) {
	got, err := bundle.Build(workload.Policy{HostDenylist: []workload.HostMatcher{}})
	if err == nil || got != nil {
		t.Fatalf("Build() = %v, %v", got, err)
	}
}
