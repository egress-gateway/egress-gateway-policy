package bundle_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
)

func ExampleBuild() {
	policy := workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "restricted.example"}}}
	archive, err := bundle.Build(policy)
	if err != nil {
		panic(err)
	}
	loaded, err := opabundle.NewReader(bytes.NewReader(archive)).Read()
	if err != nil {
		panic(err)
	}
	// OPA consumes JSON-compatible values. Serialize the public input contract.
	input := workload.Input{Version: workload.Version, Host: "sub.restricted.example", Protocol: workload.Other}
	encoded, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	var facts any
	if err := json.Unmarshal(encoded, &facts); err != nil {
		panic(err)
	}
	results, err := rego.New(rego.Query(workload.DecisionQuery), rego.ParsedBundle("workload", &loaded), rego.Input(facts), rego.StrictBuiltinErrors(true)).Eval(context.Background())
	if err != nil {
		panic(err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		panic("undefined or ambiguous workload decision")
	}
	raw, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		panic(err)
	}
	decision, err := workload.DecodeDecision(raw)
	if err != nil {
		panic(err)
	}
	fmt.Println(decision.Version, decision.Allowed, decision.Code, decision.Violations)
	// Output: v1 false deny [hostDenylist]
}
