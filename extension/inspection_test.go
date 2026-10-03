package extension

import (
	"bytes"
	"path/filepath"
	"testing"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/proto"
)

func TestUnaryInspectionAtAuthorizationBoundary(t *testing.T) {
	descriptor := stagedDescriptor(t, "model")
	p := protobufPolicy(descriptor)
	p.RequestConstraints = append(p.RequestConstraints, workload.Constraint{
		Name: "carrier", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{}},
		Require: []workload.Requirement{{Source: workload.Header, Name: new("x-tag"), Operator: workload.In, Values: []string{"good"}}},
	})
	raw, err := policybundle.BuildExecution(p, "unary")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.tar.gz")
	writeFile(t, path, raw)
	rt := startRuntime(t, Config{Role: "workload", Descriptors: []DescriptorFile{descriptor}}, []string{path}, nil)
	valid := framed([]byte{10, 4, 'g', 'o', 'o', 'd'})
	for _, tc := range []struct {
		name                  string
		body                  []byte
		encoding, contentType string
		want                  bool
	}{
		{name: "valid", body: valid, contentType: "application/grpc", want: true},
		{name: "proto-subtype", body: valid, contentType: "application/grpc+proto", want: true},
		{name: "missing", contentType: "application/grpc"},
		{name: "empty-message", body: framed(nil), contentType: "application/grpc"},
		{name: "short-frame", body: []byte{0, 0}, contentType: "application/grpc"},
		{name: "truncated", body: valid[:len(valid)-1], contentType: "application/grpc"},
		{name: "extra-frame", body: append(bytes.Clone(valid), valid...), contentType: "application/grpc"},
		{name: "compressed-frame", body: append([]byte{1}, valid[1:]...), contentType: "application/grpc"},
		{name: "encoded", body: valid, encoding: "gzip", contentType: "application/grpc"},
		{name: "JSON-subtype", body: valid, contentType: "application/grpc+json"},
		{name: "spoofed-content-type", body: valid, contentType: "application/json"},
		{name: "malformed-protobuf", body: framed([]byte{10, 255}), contentType: "application/grpc"},
		{name: "over-limit", body: make([]byte, MaxBodyBytes+1), contentType: "application/grpc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := checkRequest()
			h := req.Attributes.Request.Http
			h.Path, h.RawBody = "/test.Service/Call", tc.body
			h.HeaderMap.Headers = append(h.HeaderMap.Headers, &core.HeaderValue{Key: "content-type", Value: tc.contentType})
			if tc.encoding != "" {
				h.HeaderMap.Headers = append(h.HeaderMap.Headers, &core.HeaderValue{Key: "grpc-encoding", Value: tc.encoding})
			}
			if got := rt.allowed(t, req); got != tc.want {
				t.Fatalf("allowed=%v want=%v", got, tc.want)
			}
			if tc.want {
				h.HeaderMap.Headers[0].Value = "bad"
				if rt.allowed(t, req) {
					t.Fatal("gRPC pass bypassed HTTP carrier constraint")
				}
			}
		})
	}
}

func TestStrictJSONAtAuthorizationBoundary(t *testing.T) {
	raw, err := policybundle.BuildExecution(modelPolicy(), "json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.tar.gz")
	writeFile(t, path, raw)
	rt := startRuntime(t, Config{Role: "workload"}, []string{path}, nil)
	for _, body := range []string{`{"model":"good","model":"bad"}`, `{"model":"good","unused":{"x":1,"x":2}}`, `{"model":"good"} {}`, `{"model":"good","unused":"\ud800"}`, "{\"model\":\"good\",\"unused\":\"\xff\"}", string(bytes.Repeat([]byte(" "), MaxBodyBytes)) + `{"model":"good"}`} {
		req := checkRequest()
		req.Attributes.Request.Http.RawBody = []byte(body)
		if rt.allowed(t, req) {
			t.Fatal("ambiguous or oversized JSON was authorized")
		}
	}
	req := checkRequest()
	h := req.Attributes.Request.Http
	h.RawBody = append([]byte(`{"model":"good"}`), bytes.Repeat([]byte(" "), MaxBodyBytes-len(`{"model":"good"}`))...)
	if !rt.allowed(t, req) {
		t.Fatal("complete 64KiB JSON denied")
	}
	for _, header := range []*core.HeaderValue{{Key: "x-envoy-auth-partial-body", Value: "true"}, {Key: "content-encoding", Value: "gzip"}} {
		copy := proto.Clone(req).(*auth.CheckRequest)
		copy.Attributes.Request.Http.HeaderMap.Headers = append(copy.Attributes.Request.Http.HeaderMap.Headers, header)
		if rt.allowed(t, copy) {
			t.Fatalf("accepted %s", header.Key)
		}
	}
}
