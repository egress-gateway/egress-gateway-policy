package bundle_test

import (
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/workload"
)

const descriptorDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func httpInput() workload.Input {
	return workload.Input{
		Version: workload.Version, Host: "api.example", Protocol: workload.HTTP,
		HTTP:     &workload.HTTPRequest{Method: "POST", Path: "/v1", Headers: map[string][]string{"x-model": {"small"}}, Query: map[string][]string{"model": {"small"}}},
		Payloads: []workload.PayloadView{{Format: workload.JSON, Status: workload.Ready, Value: map[string]any{"model": "small"}}},
	}
}

func httpPolicy(requirements ...workload.Requirement) workload.Policy {
	c := workload.Constraint{Name: "models", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{Methods: []string{"POST"}, Paths: []string{"/v1"}}}, Require: requirements}
	for _, r := range requirements {
		if r.Source == workload.Payload {
			c.Decode = &workload.Decoder{Format: workload.JSON}
		}
	}
	return workload.Policy{RequestConstraints: []workload.Constraint{c}}
}

func grpcInput() workload.Input {
	in := httpInput()
	in.Protocol = workload.GRPC
	in.GRPC = &workload.GRPCRequest{Service: "inference.v1.Service", Method: "Generate", Metadata: map[string][]string{"model": {"small"}}}
	in.Payloads = []workload.PayloadView{{Format: workload.Protobuf, DescriptorDigest: descriptorDigest, Status: workload.Ready, Value: map[string]any{"model": "small"}}}
	return in
}

func grpcPolicy(requirements ...workload.Requirement) workload.Policy {
	p := httpPolicy(requirements...)
	c := &p.RequestConstraints[0]
	c.Match.HTTP = nil
	c.Match.GRPC = &workload.GRPCMatch{Service: "inference.v1.Service", Methods: []string{"Generate"}}
	if c.Decode != nil {
		c.Decode = &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &workload.ArtifactRef{URL: "https://policies.example/descriptors.pb", Digest: descriptorDigest}}
	}
	return p
}

func payloadRequirement(op workload.Operator, values ...string) workload.Requirement {
	return workload.Requirement{Source: workload.Payload, Pointer: new("/model"), Operator: op, Values: values}
}

func TestSourcesAndOperators(t *testing.T) {
	for _, source := range []workload.Source{workload.Payload, workload.Header, workload.Query, workload.GRPCMetadata} {
		for _, operator := range []workload.Operator{workload.In, workload.NotIn, workload.Exists} {
			t.Run(string(source)+"/"+string(operator), func(t *testing.T) {
				r := workload.Requirement{Source: source, Operator: operator}
				switch operator {
				case workload.In:
					r.Values = []string{"small"}
				case workload.NotIn:
					r.Values = []string{"blocked"}
				}
				switch source {
				case workload.Payload:
					r.Pointer = new("/model")
				case workload.Header:
					r.Name = new("x-model")
				default:
					r.Name = new("model")
				}
				p, in := httpPolicy(r), httpInput()
				if source == workload.GRPCMetadata {
					p, in = grpcPolicy(r), grpcInput()
				}
				eval := evaluator(t, p)
				if d := eval(in); !d.Allowed {
					t.Fatalf("present valid selection: %+v", d)
				}
				switch source {
				case workload.Payload:
					in.Payloads[0].Value = map[string]any{}
				case workload.Header:
					delete(in.HTTP.Headers, "x-model")
				case workload.Query:
					delete(in.HTTP.Query, "model")
				case workload.GRPCMetadata:
					delete(in.GRPC.Metadata, "model")
				}
				if d := eval(in); d.Allowed || d.Code != workload.Deny {
					t.Fatalf("missing selection: %+v", d)
				}
			})
		}
	}
}

func TestPayloadSelection(t *testing.T) {
	for _, tc := range []struct {
		name, pointer string
		value         any
		operator      workload.Operator
		values        []string
		allowed       bool
	}{
		{"nested", "/a/b", map[string]any{"a": map[string]any{"b": "small"}}, workload.In, []string{"small"}, true},
		{"escaped", "/a~1b/~0key", map[string]any{"a/b": map[string]any{"~key": "small"}}, workload.In, []string{"small"}, true},
		{"escape order", "/~01", map[string]any{"~1": "small"}, workload.In, []string{"small"}, true},
		{"empty key", "/", map[string]any{"": "small"}, workload.In, []string{"small"}, true},
		{"array index", "/items/0", map[string]any{"items": []any{"small"}}, workload.In, []string{"small"}, true},
		{"root array", "/0", []any{"small"}, workload.In, []string{"small"}, true},
		{"noncanonical index", "/items/00", map[string]any{"items": []any{"small"}}, workload.Exists, nil, false},
		{"numeric object key", "/00", map[string]any{"00": "small"}, workload.In, []string{"small"}, true},
		{"out of range", "/items/1", map[string]any{"items": []any{"small"}}, workload.Exists, nil, false},
		{"array not expanded", "/model", map[string]any{"model": []any{"small"}}, workload.In, []string{"small"}, false},
		{"number not coerced", "/model", map[string]any{"model": 1}, workload.In, []string{"1"}, false},
		{"no trimming", "/model", map[string]any{"model": " small "}, workload.In, []string{"small"}, false},
		{"case sensitive", "/model", map[string]any{"model": "Small"}, workload.In, []string{"small"}, false},
		{"empty string", "/model", map[string]any{"model": ""}, workload.In, []string{""}, true},
		{"null", "/model", map[string]any{"model": nil}, workload.Exists, nil, false},
		{"empty object exists", "/model", map[string]any{"model": map[string]any{}}, workload.Exists, nil, true},
		{"empty array exists", "/model", map[string]any{"model": []any{}}, workload.Exists, nil, true},
		{"root null", "/model", nil, workload.Exists, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := workload.Requirement{Source: workload.Payload, Pointer: new(tc.pointer), Operator: tc.operator, Values: tc.values}
			in := httpInput()
			in.Payloads[0].Value = tc.value
			if d := evaluator(t, httpPolicy(r))(in); d.Allowed != tc.allowed {
				t.Fatalf("decision: %+v", d)
			}
		})
	}
}

func TestRepeatedAttributes(t *testing.T) {
	for _, source := range []workload.Source{workload.Header, workload.Query, workload.GRPCMetadata} {
		for _, op := range []workload.Operator{workload.In, workload.NotIn} {
			t.Run(string(source)+"/"+string(op), func(t *testing.T) {
				r := workload.Requirement{Source: source, Name: new("model"), Operator: op, Values: []string{"small"}}
				if op == workload.NotIn {
					r.Values = []string{"blocked"}
				}
				p, in := httpPolicy(r), httpInput()
				var attrs map[string][]string
				switch source {
				case workload.Header:
					attrs = in.HTTP.Headers
				case workload.Query:
					attrs = in.HTTP.Query
				default:
					p, in = grpcPolicy(r), grpcInput()
					attrs = in.GRPC.Metadata
				}
				eval := evaluator(t, p)
				attrs["model"] = []string{"small", "small"}
				if d := eval(in); !d.Allowed {
					t.Fatalf("all values pass: %+v", d)
				}
				for _, values := range [][]string{{"small", "blocked"}, {"blocked", "small"}, {"blocked", "small", "blocked"}} {
					attrs["model"] = values
					if d := eval(in); d.Allowed {
						t.Fatalf("must inspect every value %v: %+v", values, d)
					}
				}
			})
		}
	}
}

func TestInspectionAndScope(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*workload.Input)
		allowed bool
	}{
		{"allow", func(*workload.Input) {}, true},
		{"missing payload view", func(i *workload.Input) { i.Payloads = nil }, false},
		{"decode failure", func(i *workload.Input) { i.Payloads[0].Status = workload.Invalid }, false},
		{"truncated", func(i *workload.Input) { i.Payloads[0].Status = workload.Truncated }, false},
		{"unsupported", func(i *workload.Input) { i.Payloads[0].Status = workload.Unsupported }, false},
		{"unavailable", func(i *workload.Input) { i.Payloads[0].Status = workload.Unavailable }, false},
		{"unknown protocol", func(i *workload.Input) { i.Protocol = workload.Unknown; i.HTTP = nil; i.Payloads = nil }, false},
		{"known other protocol", func(i *workload.Input) { i.Protocol = workload.Other; i.HTTP = nil; i.Payloads = nil }, true},
		{"HTTP view unavailable", func(i *workload.Input) { i.HTTP = nil }, false},
		{"known host outside scope", func(i *workload.Input) {
			i.Host = "elsewhere.example"
			i.Protocol = workload.Unknown
			i.HTTP = nil
			i.Payloads = nil
		}, true},
		{"method outside scope", func(i *workload.Input) { i.HTTP.Method = "GET"; i.Payloads = nil }, true},
		{"path outside scope", func(i *workload.Input) { i.HTTP.Path = "/other"; i.Payloads = nil }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := httpInput()
			tc.change(&in)
			if d := evaluator(t, httpPolicy(payloadRequirement(workload.In, "small")))(in); d.Allowed != tc.allowed {
				t.Fatalf("decision: %+v", d)
			}
		})
	}
}

func TestGRPCPayloadAndHTTPConjunction(t *testing.T) {
	p := grpcPolicy(payloadRequirement(workload.In, "small"))
	h := httpPolicy(workload.Requirement{Source: workload.Header, Name: new("x-model"), Operator: workload.In, Values: []string{"small"}}).RequestConstraints[0]
	h.Name = "http-carrier"
	p.RequestConstraints = append(p.RequestConstraints, h)
	eval := evaluator(t, p)
	in := grpcInput()
	if d := eval(in); !d.Allowed {
		t.Fatalf("both scopes pass: %+v", d)
	}
	in.HTTP.Headers["x-model"] = []string{"blocked"}
	if d := eval(in); d.Allowed {
		t.Fatalf("HTTP carrier must apply: %+v", d)
	}
	in = grpcInput()
	in.Payloads[0].Value = map[string]any{}
	if d := eval(in); d.Allowed {
		t.Fatalf("ProtoJSON missing field must fail: %+v", d)
	}
	in = grpcInput()
	in.Payloads[0].DescriptorDigest = "sha256:" + strings.Repeat("b", 64)
	if d := eval(in); d.Allowed {
		t.Fatalf("wrong descriptor cannot satisfy inspection: %+v", d)
	}
	// Content-type is ordinary application input, not the protocol discriminator.
	in = grpcInput()
	in.HTTP.Headers["content-type"] = []string{"application/json"}
	in.Payloads[0].Status = workload.Invalid
	if d := eval(in); d.Allowed {
		t.Fatalf("header cannot disable gRPC inspection: %+v", d)
	}
}

func TestCompositionAndAlternativeScopes(t *testing.T) {
	r := payloadRequirement(workload.In, "small")
	p := httpPolicy(r, workload.Requirement{Source: workload.Query, Name: new("model"), Operator: workload.In, Values: []string{"small"}})
	c := &p.RequestConstraints[0]
	c.Match.Hosts = append(c.Match.Hosts, workload.HostMatcher{Type: workload.DomainSuffix, Value: "other.example"})
	c.Match.HTTP.Methods = []string{"GET", "POST"}
	c.Match.HTTP.Paths = []string{"/v1", "/v2"}
	eval := evaluator(t, p)
	in := httpInput()
	in.Host = "sub.other.example"
	in.HTTP.Method = "GET"
	in.HTTP.Path = "/v2"
	if d := eval(in); !d.Allowed {
		t.Fatalf("OR within each dimension: %+v", d)
	}
	in.HTTP.Query["model"] = []string{"large"}
	if d := eval(in); d.Allowed {
		t.Fatalf("AND requirements: %+v", d)
	}
	in.Host = "api.example"
	in.HTTP.Path = "/outside"
	if d := eval(in); !d.Allowed {
		t.Fatalf("AND match dimensions: %+v", d)
	}
	p.HostDenylist = []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}
	if d := evaluator(t, p)(httpInput()); d.Allowed {
		t.Fatalf("denylist overrides passing constraint: %+v", d)
	}
	p = grpcPolicy(workload.Requirement{Source: workload.GRPCMetadata, Name: new("model"), Operator: workload.Exists})
	p.RequestConstraints[0].Match.GRPC.Methods = nil
	in = grpcInput()
	in.GRPC.Method = "OtherMethod"
	in.Payloads = nil
	if d := evaluator(t, p)(in); !d.Allowed {
		t.Fatalf("metadata-only, any method, no payload: %+v", d)
	}
	in.GRPC.Service = "OtherService"
	in.GRPC.Metadata = nil
	if d := evaluator(t, p)(in); !d.Allowed {
		t.Fatalf("different service: %+v", d)
	}
}

func TestDistinctDescriptorViews(t *testing.T) {
	p := grpcPolicy(payloadRequirement(workload.In, "small"))
	c := grpcPolicy(payloadRequirement(workload.In, "large")).RequestConstraints[0]
	c.Name = "other-descriptor"
	c.Decode.DescriptorSet.Digest = "sha256:" + strings.Repeat("b", 64)
	p.RequestConstraints = append(p.RequestConstraints, c)
	in := grpcInput()
	in.Payloads = append(in.Payloads, workload.PayloadView{Format: workload.Protobuf, DescriptorDigest: c.Decode.DescriptorSet.Digest, Status: workload.Ready, Value: map[string]any{"model": "large"}})
	eval := evaluator(t, p)
	if d := eval(in); !d.Allowed {
		t.Fatalf("each constraint uses its descriptor: %+v", d)
	}
	in.Payloads = in.Payloads[:1]
	if d := eval(in); d.Allowed {
		t.Fatalf("missing one required descriptor: %+v", d)
	}
}

func TestAttributeNormalizationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		values      []string
		allowed     bool
	}{
		{"model", "small,large", []string{"small", "large"}, false},
		{"model", "%73mall", []string{"small"}, false},
		{"Model", "small", []string{"small"}, false},
		{"model", "", []string{""}, true},
	} {
		r := workload.Requirement{Source: workload.Query, Name: new("model"), Operator: workload.In, Values: tc.values}
		in := httpInput()
		in.HTTP.Query = map[string][]string{tc.name: {tc.value}}
		if d := evaluator(t, httpPolicy(r))(in); d.Allowed != tc.allowed {
			t.Fatalf("%+v: %+v", tc, d)
		}
	}
}
