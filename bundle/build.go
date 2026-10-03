package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"

	policyrego "github.com/egress-gateway/egress-gateway-policy/internal/rego"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
)

// Root is the policy/data namespace owned by a workload bundle.
const Root = "egress_gateway/workload"

// Build validates policy and returns a standard gzipped OPA snapshot bundle.
// It performs no I/O outside the returned in-memory artifact. An error returns
// no usable artifact. Controller owns publication and gateway owns loading.
func Build(policy workload.Policy) ([]byte, error) {
	return build(policy, false, "")
}

// BuildExecution includes the authorization bridge for the Policy OPA extension.
// Revision is the publisher's identifier, exposed by OPA's native bundle status.
// Build remains available for consumers of the normalized-input query alone.
func BuildExecution(policy workload.Policy, revision string) ([]byte, error) {
	return build(policy, true, revision)
}

func build(policy workload.Policy, execution bool, revision string) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("workload policy: %w", err)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("encode workload policy: %w", err)
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, fmt.Errorf("encode workload data: %w", err)
	}
	// Bundle data has explicit collections; absent configuration is not an empty
	// policy. The public authoring model still distinguishes omitted/empty lists.
	if policy.HostDenylist == nil {
		data["hostDenylist"] = []any{}
	}
	if policy.RequestConstraints == nil {
		data["requestConstraints"] = []any{}
	}
	b := opabundle.Bundle{
		Manifest: opabundle.Manifest{Roots: new([]string{Root}), RegoVersion: new(1), Revision: revision},
		Data: map[string]any{"egress_gateway": map[string]any{"workload": map[string]any{
			"config": map[string]any{"version": workload.Version, "policy": data},
		}}},
	}
	files, err := policyrego.Modules.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read policy resources: %w", err)
	}
	for _, file := range files {
		source, err := policyrego.Modules.ReadFile(file.Name())
		if err != nil {
			return nil, fmt.Errorf("read policy module: %w", err)
		}
		b.Modules = append(b.Modules, opabundle.ModuleFile{URL: "policy/" + file.Name(), Path: "policy/" + file.Name(), Raw: source})
	}
	var output bytes.Buffer
	if execution {
		b.Data["egress_gateway"].(map[string]any)["workload"].(map[string]any)["config"].(map[string]any)["extensionVersion"] = "v1"
		b.Modules = append(b.Modules, opabundle.ModuleFile{URL: "policy/authorization.rego", Path: "policy/authorization.rego", Raw: []byte(authorization)})
	}
	if err := opabundle.NewWriter(&output).Write(b); err != nil {
		return nil, fmt.Errorf("write workload bundle: %w", err)
	}
	return output.Bytes(), nil
}

const authorization = `package egress_gateway.workload.authorization
import rego.v1

default allow := false
allow if {
 normalized := egress_gateway.inspect(input, data.egress_gateway.workload.config)
 decision := data.egress_gateway.workload.decision with input as normalized
 egress_gateway.accepts(decision)
}
`
