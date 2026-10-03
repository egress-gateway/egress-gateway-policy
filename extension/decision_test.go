package extension

import (
	"bytes"
	"path/filepath"
	"testing"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/open-policy-agent/opa/v1/bundle"
)

func TestStrictDecisionsAtAuthorizationBoundary(t *testing.T) {
	for _, decision := range []string{`true`, `{"allowed":true}`, `{"version":"v2","allowed":true,"code":"pass","violations":[]}`, `{"version":"v1","allowed":true,"code":"deny","violations":["x"]}`, `{"version":"v1","allowed":true,"code":"pass","violations":[],"extra":1}`, `null`, `{"version":"v1","allowed":true,"code":"pass","violations":null}`} {
		t.Run(decision, func(t *testing.T) {
			raw, err := policybundle.BuildExecution(workload.Policy{}, "invalid-decision")
			if err != nil {
				t.Fatal(err)
			}
			b, err := bundle.NewReader(bytes.NewReader(raw)).Read()
			if err != nil {
				t.Fatal(err)
			}
			for i := range b.Modules {
				if b.Modules[i].Path == "/policy/workload.rego" || b.Modules[i].Path == "policy/workload.rego" {
					b.Modules[i].Raw = []byte("package egress_gateway.workload\n decision := " + decision)
					b.Modules[i].Parsed = nil
				}
			}
			var output bytes.Buffer
			if err := bundle.NewWriter(&output).Write(b); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "policy.tar.gz")
			writeFile(t, file, output.Bytes())
			rt := startRuntime(t, Config{Role: "workload"}, []string{file}, nil)
			if rt.allowed(t, checkRequest()) {
				t.Fatalf("accepted malformed decision: %s", decision)
			}
		})
	}
}

func TestRuntimePeerBindingsAreIndependent(t *testing.T) {
	raw, err := policybundle.BuildExecution(workload.Policy{}, "empty")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "policy.tar.gz")
	writeFile(t, file, raw)
	a := startRuntime(t, Config{Role: "egress", AllowedPeers: []string{"spiffe://test/ns/app/sa/app"}}, []string{file}, nil)
	b := startRuntime(t, Config{Role: "egress", AllowedPeers: []string{"spiffe://test/ns/other/sa/app"}}, []string{file}, nil)
	req := checkRequest()
	req.Attributes.Request.Http.HeaderMap.Headers = append(req.Attributes.Request.Http.HeaderMap.Headers,
		&core.HeaderValue{Key: "x-forwarded-client-cert", Value: "spiffe://test/ns/other/sa/app"},
		&core.HeaderValue{Key: "x-gateway-prior-allow", Value: "true"})
	if !a.allowed(t, req) || b.allowed(t, req) {
		t.Fatal("runtime bindings mixed or application headers granted authority")
	}
	req.Attributes.Source.Principal = ""
	if a.allowed(t, req) || b.allowed(t, req) {
		t.Fatal("missing verified principal was admitted")
	}
}
