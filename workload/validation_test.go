package workload_test

import (
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/workload"
)

func validConstraint() workload.Constraint {
	return workload.Constraint{Name: "model", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/model"), Operator: workload.In, Values: []string{"small"}}}}
}

func TestConstraintValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*workload.Constraint)
		field  string
	}{
		{"name", func(c *workload.Constraint) { c.Name = "Bad" }, ".name"},
		{"hosts missing", func(c *workload.Constraint) { c.Match.Hosts = nil }, ".match.hosts"},
		{"both scopes", func(c *workload.Constraint) { c.Match.GRPC = &workload.GRPCMatch{Service: "S"} }, ".match"},
		{"neither scope", func(c *workload.Constraint) { c.Match.HTTP = nil }, ".match"},
		{"empty methods", func(c *workload.Constraint) { c.Match.HTTP.Methods = []string{} }, ".methods"},
		{"lower method", func(c *workload.Constraint) { c.Match.HTTP.Methods = []string{"post"} }, ".methods"},
		{"duplicate method", func(c *workload.Constraint) { c.Match.HTTP.Methods = []string{"GET", "GET"} }, ".methods"},
		{"path query", func(c *workload.Constraint) { c.Match.HTTP.Paths = []string{"/v1?x=1"} }, ".paths"},
		{"path whitespace", func(c *workload.Constraint) { c.Match.HTTP.Paths = []string{"/v 1"} }, ".paths"},
		{"missing decode", func(c *workload.Constraint) { c.Decode = nil }, ".require"},
		{"wrong decoder", func(c *workload.Constraint) { c.Decode.Format = workload.Protobuf }, ".decode"},
		{"JSON descriptor", func(c *workload.Constraint) { c.Decode.DescriptorSet = &workload.ArtifactRef{} }, ".decode"},
		{"unknown decoder", func(c *workload.Constraint) { c.Decode.Format = "XML" }, ".decode"},
		{"empty requirements", func(c *workload.Constraint) { c.Require = nil }, ".require"},
		{"bad pointer", func(c *workload.Constraint) { c.Require[0].Pointer = new("/bad~2") }, ".require"},
		{"empty pointer", func(c *workload.Constraint) { c.Require[0].Pointer = new("") }, ".require"},
		{"extra selector", func(c *workload.Constraint) { c.Require[0].Name = new("") }, ".require"},
		{"unknown source", func(c *workload.Constraint) { c.Require[0].Source = "Body" }, ".source"},
		{"unknown operator", func(c *workload.Constraint) { c.Require[0].Operator = "Equals" }, ".operator"},
		{"missing membership set", func(c *workload.Constraint) { c.Require[0].Values = nil }, ".values"},
		{"duplicate membership set", func(c *workload.Constraint) { c.Require[0].Values = []string{"small", "small"} }, ".values"},
		{"Exists with empty values", func(c *workload.Constraint) {
			c.Require[0].Operator = workload.Exists
			c.Require[0].Values = []string{}
		}, ".values"},
		{"uppercase header", func(c *workload.Constraint) {
			c.Require = []workload.Requirement{{Source: workload.Header, Name: new("X-Model"), Operator: workload.Exists}}
		}, ".name"},
		{"metadata HTTP scope", func(c *workload.Constraint) {
			c.Require = []workload.Requirement{{Source: workload.GRPCMetadata, Name: new("model"), Operator: workload.Exists}}
		}, ".require"},
		{"too many requirements", func(c *workload.Constraint) {
			r := c.Require[0]
			for range 32 {
				c.Require = append(c.Require, r)
			}
		}, ".require"},
		{"overlong value", func(c *workload.Constraint) { c.Require[0].Values = []string{strings.Repeat("x", 257)} }, ".values"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConstraint()
			tc.mutate(&c)
			err := (workload.Policy{RequestConstraints: []workload.Constraint{c}}).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("Validate()=%v; want field %s", err, tc.field)
			}
		})
	}
	c := validConstraint()
	if err := (workload.Policy{RequestConstraints: []workload.Constraint{c}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (workload.Policy{RequestConstraints: []workload.Constraint{c, c}}).Validate(); err == nil {
		t.Fatal("accepted duplicate names")
	}
	c.Require[0].Values = []string{strings.Repeat("界", 256)}
	if err := (workload.Policy{RequestConstraints: []workload.Constraint{c}}).Validate(); err != nil {
		t.Fatalf("Unicode character boundary: %v", err)
	}
}

func TestGRPCValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*workload.Constraint)
		valid  bool
	}{
		{"valid", func(*workload.Constraint) {}, true},
		{"service", func(c *workload.Constraint) { c.Match.GRPC.Service = "bad/service" }, false},
		{"method", func(c *workload.Constraint) { c.Match.GRPC.Methods = []string{"bad-method"} }, false},
		{"missing descriptor", func(c *workload.Constraint) { c.Decode.DescriptorSet = nil }, false},
		{"URL scheme", func(c *workload.Constraint) { c.Decode.DescriptorSet.URL = "http://api.example/d.pb" }, false},
		{"URL missing host", func(c *workload.Constraint) { c.Decode.DescriptorSet.URL = "https:///d.pb" }, false},
		{"digest", func(c *workload.Constraint) { c.Decode.DescriptorSet.Digest = "sha256:bad" }, false},
		{"binary metadata", func(c *workload.Constraint) {
			c.Require = []workload.Requirement{{Source: workload.GRPCMetadata, Name: new("data-bin"), Operator: workload.Exists}}
		}, false},
		{"text metadata", func(c *workload.Constraint) {
			c.Decode = nil
			c.Require = []workload.Requirement{{Source: workload.GRPCMetadata, Name: new("model"), Operator: workload.Exists}}
		}, true},
		{"header gRPC scope", func(c *workload.Constraint) {
			c.Require = []workload.Requirement{{Source: workload.Header, Name: new("model"), Operator: workload.Exists}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConstraint()
			c.Match.HTTP = nil
			c.Match.GRPC = &workload.GRPCMatch{Service: "pkg.Service"}
			c.Decode = &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &workload.ArtifactRef{URL: "https://api.example/d.pb", Digest: "sha256:" + strings.Repeat("a", 64)}}
			tc.mutate(&c)
			err := (workload.Policy{RequestConstraints: []workload.Constraint{c}}).Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("Validate()=%v", err)
			}
		})
	}
}
