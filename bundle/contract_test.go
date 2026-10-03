package bundle_test

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"
)

func inputMap(t *testing.T) map[string]any {
	t.Helper()
	b, err := json.Marshal(httpInput())
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMalformedInput(t *testing.T) {
	eval := evaluator(t, workload.Policy{})
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing version", func(i map[string]any) { delete(i, "version") }},
		{"unknown version", func(i map[string]any) { i["version"] = "v2" }},
		{"host uppercase", func(i map[string]any) { i["host"] = "API.example" }},
		{"host port", func(i map[string]any) { i["host"] = "api.example:443" }},
		{"host empty", func(i map[string]any) { i["host"] = "" }},
		{"unknown discriminator", func(i map[string]any) { i["protocol"] = "TLS" }},
		{"contradictory protocol", func(i map[string]any) { i["protocol"] = "Other" }},
		{"wrong HTTP type", func(i map[string]any) { i["http"] = false }},
		{"missing method", func(i map[string]any) { delete(i["http"].(map[string]any), "method") }},
		{"query in path", func(i map[string]any) { i["http"].(map[string]any)["path"] = "/v1?x=1" }},
		{"uppercase header", func(i map[string]any) {
			i["http"].(map[string]any)["headers"] = map[string]any{"X-Model": []string{"small"}}
		}},
		{"empty values", func(i map[string]any) { i["http"].(map[string]any)["query"] = map[string]any{"model": []string{}} }},
		{"scalar values", func(i map[string]any) { i["http"].(map[string]any)["headers"] = map[string]any{"x-model": "small"} }},
		{"numeric values", func(i map[string]any) { i["http"].(map[string]any)["query"] = map[string]any{"model": []any{1}} }},
		{"payload object", func(i map[string]any) { i["payloads"] = map[string]any{} }},
		{"duplicate payload views", func(i map[string]any) { v := i["payloads"].([]any)[0]; i["payloads"] = []any{v, v} }},
		{"unknown payload status", func(i map[string]any) { i["payloads"].([]any)[0].(map[string]any)["status"] = "Success" }},
		{"payload missing value", func(i map[string]any) { delete(i["payloads"].([]any)[0].(map[string]any), "value") }},
		{"wrong payload format", func(i map[string]any) { i["payloads"].([]any)[0].(map[string]any)["format"] = "XML" }},
		{"JSON descriptor", func(i map[string]any) {
			i["payloads"].([]any)[0].(map[string]any)["descriptorDigest"] = descriptorDigest
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := inputMap(t)
			tc.change(i)
			if d := eval(i); d.Allowed || d.Code != workload.InvalidInput {
				t.Fatalf("decision: %+v", d)
			}
		})
	}
	for _, i := range []any{nil, true, []any{}, "request"} {
		if d := eval(i); d.Code != workload.InvalidInput {
			t.Fatalf("%v: %+v", i, d)
		}
	}
	for _, host := range []string{"192.0.2.1", "2001:db8::1"} {
		if d := eval(workload.Input{Version: workload.Version, Host: host, Protocol: workload.Other}); !d.Allowed {
			t.Fatalf("IP target %s: %+v", host, d)
		}
	}
}

func TestBundleContractAndMissingData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*opabundle.Bundle)
	}{
		{"valid", func(*opabundle.Bundle) {}},
		{"missing config", func(b *opabundle.Bundle) { b.Data = map[string]any{} }},
		{"wrong version", func(b *opabundle.Bundle) { config(b)["version"] = "v2" }},
		{"missing policy", func(b *opabundle.Bundle) { delete(config(b), "policy") }},
		{"missing constraints", func(b *opabundle.Bundle) { delete(config(b)["policy"].(map[string]any), "requestConstraints") }},
		{"null denylist", func(b *opabundle.Bundle) { config(b)["policy"].(map[string]any)["hostDenylist"] = nil }},
		{"missing requirements", func(b *opabundle.Bundle) { delete(firstConstraint(b), "require") }},
		{"empty requirements", func(b *opabundle.Bundle) { firstConstraint(b)["require"] = []any{} }},
		{"wrong operator", func(b *opabundle.Bundle) {
			firstConstraint(b)["require"].([]any)[0].(map[string]any)["operator"] = "Allow"
		}},
		{"missing hosts", func(b *opabundle.Bundle) { delete(firstConstraint(b)["match"].(map[string]any), "hosts") }},
		{"both protocols", func(b *opabundle.Bundle) {
			firstConstraint(b)["match"].(map[string]any)["grpc"] = map[string]any{"service": "S"}
		}},
		{"bad decoder", func(b *opabundle.Bundle) { firstConstraint(b)["decode"] = map[string]any{"format": "XML"} }},
		{"duplicate names", func(b *opabundle.Bundle) {
			c := firstConstraint(b)
			config(b)["policy"].(map[string]any)["requestConstraints"] = []any{c, c}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := bundle.Build(httpPolicy(payloadRequirement(workload.In, "small")))
			if err != nil {
				t.Fatal(err)
			}
			b, err := opabundle.NewReader(bytes.NewReader(raw)).Read()
			if err != nil {
				t.Fatal(err)
			}
			if b.Manifest.RegoVersion == nil || *b.Manifest.RegoVersion != 1 || b.Manifest.Roots == nil || !slices.Equal(*b.Manifest.Roots, []string{bundle.Root}) {
				t.Fatalf("manifest: %+v", b.Manifest)
			}
			tc.change(&b)
			d := bundleEvaluator(t, b)(httpInput())
			if tc.name == "valid" {
				if !d.Allowed {
					t.Fatalf("%+v", d)
				}
			} else if d.Allowed || d.Code != workload.InvalidPolicy {
				t.Fatalf("%+v", d)
			}
		})
	}
}
func config(b *opabundle.Bundle) map[string]any {
	return b.Data["egress_gateway"].(map[string]any)["workload"].(map[string]any)["config"].(map[string]any)
}
func firstConstraint(b *opabundle.Bundle) map[string]any {
	return config(b)["policy"].(map[string]any)["requestConstraints"].([]any)[0].(map[string]any)
}

func TestSharedSemanticFixture(t *testing.T) {
	raw, err := os.ReadFile("../testdata/workload/http-model.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Policy workload.Policy `json:"policy"`
		Cases  []struct {
			Name     string            `json:"name"`
			Input    workload.Input    `json:"input"`
			Expected workload.Decision `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	eval := evaluator(t, fixture.Policy)
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			d := eval(c.Input)
			if d.Version != c.Expected.Version || d.Allowed != c.Expected.Allowed || d.Code != c.Expected.Code || !slices.Equal(d.Violations, c.Expected.Violations) {
				t.Fatalf("got %+v, want %+v", d, c.Expected)
			}
		})
	}
}
