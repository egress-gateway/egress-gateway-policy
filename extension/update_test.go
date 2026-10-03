package extension

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/plugins"
	bundleplugin "github.com/open-policy-agent/opa/v1/plugins/bundle"
	"github.com/open-policy-agent/opa/v1/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

type bundleSource struct {
	mu     sync.Mutex
	raw    []byte
	status int
}

func (s *bundleSource) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(s.raw)
}
func (s *bundleSource) publish(t *testing.T, p workload.Policy, revision string) {
	t.Helper()
	raw, err := policybundle.BuildExecution(p, revision)
	if err != nil {
		t.Fatal(err)
	}
	s.replace(raw, 0)
}
func (s *bundleSource) replace(raw []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw, s.status = raw, status
}
func nativeRuntime(t *testing.T, cfg Config, source *bundleSource) *testRuntime {
	t.Helper()
	server := httptest.NewServer(source)
	t.Cleanup(server.Close)
	return startRuntime(t, cfg, nil, map[string]any{
		"services": map[string]any{"test": map[string]any{"url": server.URL}},
		"bundles":  map[string]any{"policy": map[string]any{"service": "test", "resource": "policy.tar.gz", "trigger": "manual"}},
	})
}
func (r *testRuntime) update(t *testing.T) error {
	t.Helper()
	return bundleplugin.Lookup(r.runtime.Manager).Trigger(t.Context())
}
func (r *testRuntime) revision(t *testing.T) string {
	t.Helper()
	var revision string
	err := storage.Txn(t.Context(), r.runtime.Store, storage.TransactionParams{}, func(txn storage.Transaction) error {
		var err error
		revision, err = bundle.ReadBundleRevisionFromStore(t.Context(), r.runtime.Store, txn, "policy")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return revision
}
func (r *testRuntime) ready(t *testing.T, want bool) {
	t.Helper()
	status := r.runtime.Manager.PluginStatus()[PluginName]
	if status == nil || (status.State == plugins.StateOK) != want {
		t.Fatalf("extension status=%+v, want ready=%v", status, want)
	}
}
func modelPolicy() workload.Policy {
	return workload.Policy{RequestConstraints: []workload.Constraint{{Name: "model", Match: workload.Match{Hosts: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}, HTTP: &workload.HTTPMatch{}}, Decode: &workload.Decoder{Format: workload.JSON}, Require: []workload.Requirement{{Source: workload.Payload, Pointer: new("/model"), Operator: workload.In, Values: []string{"good"}}}}}}
}
func stagedDescriptor(t *testing.T, jsonName string) DescriptorFile {
	t.Helper()
	files := protoFiles(t, jsonName, false)
	var set descriptorpb.FileDescriptorSet
	files.RangeFiles(func(f protoreflect.FileDescriptor) bool {
		set.File = append(set.File, protodesc.ToFileDescriptorProto(f))
		return true
	})
	raw, err := proto.Marshal(&set)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "api.pb")
	writeFile(t, path, raw)
	return DescriptorFile{URL: "https://artifact.example/api.pb", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), Path: path}
}
func protobufPolicy(d DescriptorFile) workload.Policy {
	p := modelPolicy()
	c := &p.RequestConstraints[0]
	c.Match.HTTP = nil
	c.Match.GRPC = &workload.GRPCMatch{Service: "test.Service", Methods: []string{"Call"}}
	c.Decode = &workload.Decoder{Format: workload.Protobuf, DescriptorSet: &workload.ArtifactRef{URL: d.URL, Digest: d.Digest}}
	return p
}
func TestNativeUpdatesFollowInspectionAndRecover(t *testing.T) {
	for _, role := range []string{"workload", "egress"} {
		t.Run(role, func(t *testing.T) {
			descriptor := stagedDescriptor(t, "model")
			other := stagedDescriptor(t, "otherModel")
			source := &bundleSource{status: http.StatusServiceUnavailable}
			r := nativeRuntime(t, Config{Role: role, AllowedPeers: []string{"spiffe://test/ns/app/sa/app"}, Descriptors: []DescriptorFile{descriptor, other}}, source)
			req := checkRequest()
			r.ready(t, false)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			_, err := r.client.Check(ctx, req, grpc.WaitForReady(true))
			cancel()
			if status.Code(err) != codes.Unknown || status.Convert(err).Message() != "undefined decision" {
				t.Fatalf("expected fail-closed undefined decision before first bundle, got %v", err)
			}
			if err := r.update(t); err == nil {
				t.Fatal("first download failure not reported")
			}
			r.ready(t, false)
			source.publish(t, workload.Policy{}, "empty")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			r.ready(t, true)
			if !r.allowed(t, req) {
				t.Fatal("valid empty bundle denied")
			}
			req.Attributes.Request.Http.RawBody = []byte(`{"model":"bad"}`)
			if !r.allowed(t, req) {
				t.Fatal("empty policy acquired decoder")
			}
			source.publish(t, modelPolicy(), "json")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			if r.allowed(t, req) {
				t.Fatal("new JSON inspection not enforced")
			}
			req.Attributes.Request.Http.RawBody = []byte(`{"model":"good"}`)
			if !r.allowed(t, req) {
				t.Fatal("JSON update not usable")
			}
			req.Attributes.Request.Http.Path = "/test.Service/Call"
			req.Attributes.Request.Http.HeaderMap.Headers = []*core.HeaderValue{{Key: "content-type", Value: "application/grpc"}}
			req.Attributes.Request.Http.RawBody = framed([]byte{10, 4, 'g', 'o', 'o', 'd'})
			source.publish(t, protobufPolicy(descriptor), "proto")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			if !r.allowed(t, req) {
				t.Fatal("updated Protobuf decoder not used")
			}
			source.publish(t, protobufPolicy(other), "other-view")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			if r.allowed(t, req) {
				t.Fatal("new descriptor used old decoded view")
			}
			missing := descriptor
			missing.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			source.publish(t, protobufPolicy(missing), "missing-dependency")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			r.ready(t, false)
			if r.allowed(t, req) {
				t.Fatal("missing dependency used stale decoder")
			}
			incompatible := protobufPolicy(descriptor)
			incompatible.RequestConstraints[0].Match.GRPC.Methods = []string{"Missing"}
			source.publish(t, incompatible, "incompatible")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			r.ready(t, false)
			if r.allowed(t, req) {
				t.Fatal("incompatible policy authorized")
			}
			source.publish(t, protobufPolicy(descriptor), "recovered")
			if err := r.update(t); err != nil {
				t.Fatal(err)
			}
			r.ready(t, true)
			if !r.allowed(t, req) || r.revision(t) != "recovered" {
				t.Fatal("valid update did not recover")
			}
			// Runtime-owned descriptor snapshots remain usable after staged files change.
			writeFile(t, descriptor.Path, []byte("replaced bytes"))
			if !r.allowed(t, req) {
				t.Fatal("request reread descriptor artifact")
			}
		})
	}
}
func TestNativeFailuresRetainLastActivatedBundle(t *testing.T) {
	source := &bundleSource{}
	source.publish(t, workload.Policy{}, "good")
	r := nativeRuntime(t, Config{Role: "workload"}, source)
	var statusMu sync.Mutex
	var lastStatus bundleplugin.Status
	bundleplugin.Lookup(r.runtime.Manager).Register("test", func(s bundleplugin.Status) {
		statusMu.Lock()
		defer statusMu.Unlock()
		lastStatus = s
	})
	if err := r.update(t); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"download", "load", "compile"} {
		t.Run(failure, func(t *testing.T) {
			switch failure {
			case "download":
				source.replace(nil, http.StatusServiceUnavailable)
			case "load":
				source.replace([]byte("not a bundle"), 0)
			case "compile":
				raw, err := policybundle.BuildExecution(workload.Policy{}, "failed")
				if err != nil {
					t.Fatal(err)
				}
				b, err := bundle.NewReader(bytes.NewReader(raw)).Read()
				if err != nil {
					t.Fatal(err)
				}
				b.Modules = append(b.Modules, bundle.ModuleFile{URL: "bad.rego", Path: "bad.rego", Raw: []byte("package egress_gateway.workload.bad\nvalue := missing_builtin()")})
				var output bytes.Buffer
				if err := bundle.NewWriter(&output).Write(b); err != nil {
					t.Fatal(err)
				}
				source.replace(output.Bytes(), 0)
			}
			_ = r.update(t) // OPA reports activation errors through bundle status.
			statusMu.Lock()
			observed := lastStatus
			statusMu.Unlock()
			if observed.Code == "" || observed.ActiveRevision != "good" {
				t.Fatalf("native failure status=%+v", observed)
			}
			if r.revision(t) != "good" || !r.allowed(t, checkRequest()) {
				t.Fatal("failure replaced the last active policy")
			}
			r.ready(t, true)
		})
	}
	source.publish(t, workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "api.example"}}}, "deny")
	if err := r.update(t); err != nil {
		t.Fatal(err)
	}
	if r.revision(t) != "deny" || r.allowed(t, checkRequest()) {
		t.Fatal("recovery did not enforce new bundle")
	}
}

func TestConcurrentNativeUpdatesKeepPolicyAndDecoderTogether(t *testing.T) {
	first := stagedDescriptor(t, "model")
	second := stagedDescriptor(t, "otherModel")
	a, b := protobufPolicy(first), protobufPolicy(second)
	b.RequestConstraints[0].Require[0].Pointer = new("/otherModel")
	source := &bundleSource{}
	source.publish(t, a, "initial")
	r := nativeRuntime(t, Config{Role: "workload", Descriptors: []DescriptorFile{first, second}}, source)
	if err := r.update(t); err != nil {
		t.Fatal(err)
	}
	req := checkRequest()
	h := req.Attributes.Request.Http
	h.Path, h.RawBody = "/test.Service/Call", framed([]byte{10, 4, 'g', 'o', 'o', 'd'})
	h.HeaderMap.Headers = []*core.HeaderValue{{Key: "content-type", Value: "application/grpc"}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	started := make(chan struct{})
	failures := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		close(started)
		for range 100 {
			response, err := r.client.Check(ctx, req, grpc.WaitForReady(true))
			if err != nil {
				failures <- err
				return
			}
			if response.GetStatus().GetCode() != int32(codes.OK) {
				failures <- fmt.Errorf("mixed policy/decoder denied a request valid in both revisions")
				return
			}
		}
	})
	<-started
	for i := range 12 {
		policy := a
		if i%2 != 0 {
			policy = b
		}
		source.publish(t, policy, fmt.Sprintf("revision-%d", i))
		if err := r.update(t); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
}
