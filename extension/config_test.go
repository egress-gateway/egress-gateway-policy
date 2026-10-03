package extension

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/open-policy-agent/opa/v1/bundle"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestConfigurationRejectsUntrustedOrIncompatibleSupply(t *testing.T) {
	for _, c := range []Config{{}, {Role: "other"}, {Role: "egress"}, {Role: "egress", AllowedPeers: []string{"spiffe://mesh/ns/*/sa/app"}}} {
		if _, err := loadConfig(c); err == nil {
			t.Fatalf("accepted invalid configuration %+v", c)
		}
	}
	d := stagedDescriptor(t, "model")
	c := Config{Role: "workload", Descriptors: []DescriptorFile{d}}
	if _, err := loadConfig(c); err != nil {
		t.Fatal(err)
	}
	c.Descriptors = append(c.Descriptors, d)
	if _, err := loadConfig(c); err == nil {
		t.Fatal("duplicate reference accepted")
	}
	c.Descriptors = c.Descriptors[:1]
	writeFile(t, d.Path, []byte("different bytes"))
	if _, err := loadConfig(c); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	d = stagedDescriptor(t, "model")
	raw, err := os.ReadFile(d.Path)
	if err != nil {
		t.Fatal(err)
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	set.File[0].Dependency = []string{"missing.proto"}
	raw, err = proto.Marshal(&set)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, d.Path, raw)
	d.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if _, err := loadConfig(Config{Role: "workload", Descriptors: []DescriptorFile{d}}); err == nil {
		t.Fatal("missing descriptor import accepted")
	}
}

func TestIncompleteArtifactsAreNotReady(t *testing.T) {
	for _, tc := range []string{"core-only", "missing-bridge", "missing-decision"} {
		t.Run(tc, func(t *testing.T) {
			var raw []byte
			var err error
			if tc == "core-only" {
				raw, err = policybundle.Build(workload.Policy{})
			} else {
				raw, err = policybundle.BuildExecution(workload.Policy{}, "incomplete")
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc != "core-only" {
				b, err := bundle.NewReader(bytes.NewReader(raw)).Read()
				if err != nil {
					t.Fatal(err)
				}
				var modules []bundle.ModuleFile
				for _, m := range b.Modules {
					name := filepath.Base(m.Path)
					if (tc == "missing-bridge" && name == "authorization.rego") || (tc == "missing-decision" && name == "workload.rego") {
						continue
					}
					modules = append(modules, m)
				}
				b.Modules = modules
				var out bytes.Buffer
				if err := bundle.NewWriter(&out).Write(b); err != nil {
					t.Fatal(err)
				}
				raw = out.Bytes()
			}
			path := filepath.Join(t.TempDir(), "policy.tar.gz")
			writeFile(t, path, raw)
			r := startRuntime(t, Config{Role: "workload"}, []string{path}, nil)
			r.ready(t, false)
		})
	}
}
