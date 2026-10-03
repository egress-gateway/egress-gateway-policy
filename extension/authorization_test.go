package extension

import (
	"github.com/egress-gateway/egress-gateway-policy/workload"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"testing"
)

func checkRequest() *auth.CheckRequest {
	return &auth.CheckRequest{Attributes: &auth.AttributeContext{Source: &auth.AttributeContext_Peer{Principal: "spiffe://test/ns/app/sa/app"}, Request: &auth.AttributeContext_Request{Http: &auth.AttributeContext_HttpRequest{Method: "POST", Host: "api.example:443", Scheme: "https", Path: "/v1/chat?tag=good", Protocol: "HTTP/2", HeaderMap: &core.HeaderMap{Headers: []*core.HeaderValue{{Key: "x-tag", Value: "good"}}}, RawBody: []byte(`{"model":"good","items":[{"name":"good"}]}`)}}}}
}
func TestSharedSelectorsAndOperators(t *testing.T) {
	for _, source := range []workload.Source{workload.Header, workload.Query, workload.Payload, workload.GRPCMetadata} {
		for _, op := range []workload.Operator{workload.In, workload.NotIn, workload.Exists} {
			t.Run(string(source)+"/"+string(op), func(t *testing.T) {
				requirement := workload.Requirement{Source: source, Operator: op}
				if op == workload.In {
					requirement.Values = []string{"good"}
				}
				if op == workload.NotIn {
					requirement.Values = []string{"bad"}
				}
				match := workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{Methods: []string{"POST"}, Paths: []string{"/v1/chat"}}}
				var decoder *workload.Decoder
				req := checkRequest()
				switch source {
				case workload.Header:
					requirement.Name = new("x-tag")
				case workload.Query:
					requirement.Name = new("tag")
				case workload.Payload:
					requirement.Pointer = new("/items/0/name")
					decoder = &workload.Decoder{Format: workload.JSON}
				case workload.GRPCMetadata:
					requirement.Name = new("x-tag")
					match.HTTP = nil
					match.GRPC = &workload.GRPCMatch{Service: "test.Service", Methods: []string{"Call"}}
					req.Attributes.Request.Http.Path = "/test.Service/Call"
				}
				p := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "selection", Match: match, Decode: decoder, Require: []workload.Requirement{requirement}}}}
				if !evaluate(t, p, "workload", req) {
					t.Fatal("valid selection denied")
				}
				http := req.Attributes.Request.Http
				switch source {
				case workload.Header, workload.GRPCMetadata:
					http.HeaderMap.Headers = append(http.HeaderMap.Headers, &core.HeaderValue{Key: "x-tag", Value: "bad"})
				case workload.Query:
					http.Path += "&tag=bad"
				case workload.Payload:
					http.RawBody = []byte(`{"items":[{"name":"bad"}]}`)
				}
				if got := evaluate(t, p, "workload", req); got != (op == workload.Exists) {
					t.Fatalf("bad/repeated value allowed=%v", got)
				}
				switch source {
				case workload.Header, workload.GRPCMetadata:
					http.HeaderMap.Headers = nil
				case workload.Query:
					http.Path = "/v1/chat"
				case workload.Payload:
					http.RawBody = []byte(`{"items":[{"name":null}]}`)
				}
				if evaluate(t, p, "workload", req) {
					t.Fatal("missing/null value allowed")
				}
			})
		}
	}
}
func TestBaselineAndIndependentPeerAdmission(t *testing.T) {
	req := checkRequest()
	if !evaluate(t, workload.Policy{}, "workload", req) || !evaluate(t, workload.Policy{}, "egress", req) {
		t.Fatal("valid empty baseline denied")
	}
	req.Attributes.Source.Principal = "spiffe://test/ns/other/sa/app"
	if evaluate(t, workload.Policy{}, "egress", req) {
		t.Fatal("empty baseline bypassed peer admission")
	}
	if evaluate(t, workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "example"}}}, "workload", req) {
		t.Fatal("denied host allowed")
	}
}
func TestPayloadScopeAndRepresentation(t *testing.T) {
	p := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "json", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{Methods: []string{"POST"}, Paths: []string{"/v1/chat"}}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/a~1b/~0/0/"), Operator: workload.In, Values: []string{""}}}}}}
	for _, tc := range []struct {
		name, body, path, method, host string
		want                           bool
	}{
		{"escaped-pointer-empty-value", `{"a/b":{"~":[{"":""}]}}`, "/v1/chat", "POST", "api.example:443", true},
		{"numeric-not-string", `{"a/b":{"~":[{"":1}]}}`, "/v1/chat", "POST", "api.example:443", false},
		{"null", `null`, "/v1/chat", "POST", "api.example:443", false},
		{"missing", `{}`, "/v1/chat", "POST", "api.example:443", false},
		{"unmatched-method", `bad JSON`, "/v1/chat", "GET", "api.example:443", true},
		{"unmatched-path", `bad JSON`, "/other", "POST", "api.example:443", true},
		{"host-boundary", `bad JSON`, "/v1/chat", "POST", "not-api.example:443", true},
		{"alternate-path", `bad JSON`, "/v1/%63hat", "POST", "api.example:443", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := checkRequest()
			h := req.Attributes.Request.Http
			h.RawBody = []byte(tc.body)
			h.Path = tc.path
			h.Method = tc.method
			h.Host = tc.host
			if got := evaluate(t, p, "workload", req); got != tc.want {
				t.Fatalf("allowed=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestConstraintConjunctionAndRequiredDecoder(t *testing.T) {
	req := checkRequest()
	match := workload.Match{Hosts: []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "example"}}, HTTP: &workload.HTTPMatch{}}
	requirement := workload.Requirement{Source: workload.Header, Name: new("x-tag"), Operator: workload.In, Values: []string{"good"}}
	p := workload.Policy{RequestConstraints: []workload.Constraint{{Name: "attributes", Match: match, Require: []workload.Requirement{requirement}}, {Name: "required-json", Match: match, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{requirement}}}}
	if !evaluate(t, p, "workload", req) {
		t.Fatal("matching constraints denied valid request")
	}
	req.Attributes.Request.Http.RawBody = []byte("invalid")
	if evaluate(t, p, "workload", req) {
		t.Fatal("attribute pass overrode declared decoder failure")
	}
	p.RequestConstraints = p.RequestConstraints[:1]
	if !evaluate(t, p, "workload", req) {
		t.Fatal("attribute-only rule acquired payload dependency")
	}
	req.Attributes.Request.Http.HeaderMap = nil
	req.Attributes.Request.Http.Headers = map[string]string{"x-tag": "good"}
	if evaluate(t, p, "workload", req) {
		t.Fatal("lossy header map passed required inspection")
	}
}
