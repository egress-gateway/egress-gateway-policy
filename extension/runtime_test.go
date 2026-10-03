package extension

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	policybundle "github.com/egress-gateway/egress-gateway-policy/bundle"
	"github.com/egress-gateway/egress-gateway-policy/workload"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoyplugin "github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/v1/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

type testRuntime struct {
	runtime *runtime.Runtime
	client  auth.AuthorizationClient
}

func startRuntime(t *testing.T, cfg Config, paths []string, extra map[string]any) *testRuntime {
	t.Helper()
	Register()
	runtime.RegisterPlugin(envoyplugin.PluginName, envoyplugin.Factory{})
	// Keep the socket below the Unix sockaddr path limit, including on macOS.
	dir, err := os.MkdirTemp("", "policy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "auth.sock")
	config := map[string]any{"plugins": map[string]any{
		PluginName:             cfg,
		envoyplugin.PluginName: map[string]any{"addr": "unix://" + socket, "path": DecisionPath, "skip-request-body-parse": true},
	}}
	for key, value := range extra {
		config[key] = value
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "opa.json")
	writeFile(t, file, raw)
	params := runtime.NewParams()
	params.ConfigFile = file
	params.BundleMode = true
	params.Paths = paths
	rt, err := runtime.NewRuntime(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Manager.Stop(context.Background()) })
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &testRuntime{runtime: rt, client: auth.NewAuthorizationClient(conn)}
}

func (r *testRuntime) allowed(t *testing.T, req *auth.CheckRequest) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, err := r.client.Check(ctx, req, grpc.WaitForReady(true))
	if err != nil {
		t.Fatal(err)
	}
	return response.GetStatus().GetCode() == int32(codes.OK)
}

func evaluate(t *testing.T, p workload.Policy, role string, req *auth.CheckRequest) bool {
	t.Helper()
	archive, err := policybundle.BuildExecution(p, "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.tar.gz")
	writeFile(t, path, archive)
	rt := startRuntime(t, Config{Role: role, AllowedPeers: []string{"spiffe://test/ns/app/sa/app"}}, []string{path}, nil)
	return rt.allowed(t, req)
}
