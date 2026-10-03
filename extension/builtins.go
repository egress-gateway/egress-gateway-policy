package extension

import (
	"encoding/json"
	"fmt"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
	"google.golang.org/protobuf/encoding/protojson"
)

var inspectDeclaration = &rego.Function{Name: "egress_gateway.inspect", Decl: types.NewFunction(types.Args(types.A, types.A), types.A)}
var acceptDeclaration = &rego.Function{Name: "egress_gateway.accepts", Decl: types.NewFunction(types.Args(types.A), types.B)}

func inspect(ctx rego.BuiltinContext, input, policy *ast.Term) (*ast.Term, error) {
	instance, ok := instances.Load(ctx.Runtime)
	if !ok {
		return nil, fmt.Errorf("workload extension is not configured")
	}
	a, err := instance.(*policyPlugin).forPolicy(policy.Value)
	if err != nil {
		return nil, err
	}

	value, err := ast.JSON(input.Value)
	if err != nil {
		return nil, err
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing Envoy attributes")
	}
	// The plugin's protobuf reflection map is not ProtoJSON for well-known
	// types such as request.time. Decode only the request facts we consume.
	attributes, _ := fields["attributes"].(map[string]any)
	request, _ := attributes["request"].(map[string]any)
	source, _ := attributes["source"].(map[string]any)
	facts := map[string]any{"attributes": map[string]any{
		"request": map[string]any{"http": request["http"]},
		"source":  map[string]any{"principal": source["principal"]},
	}}
	raw, err := json.Marshal(facts)
	if err != nil {
		return nil, err
	}
	var req auth.CheckRequest
	if err := protojson.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid Envoy facts: %w", err)
	}
	normalized, err := a.Normalize(&req)
	if err != nil {
		return nil, err
	}
	result, err := ast.InterfaceToValue(normalized)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(result), nil
}
func accepts(_ rego.BuiltinContext, term *ast.Term) (*ast.Term, error) {
	value, err := ast.JSON(term.Value)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decision, err := workload.DecodeDecision(raw)
	if err != nil {
		return nil, err
	}
	return ast.BooleanTerm(decision.Allowed), nil
}
