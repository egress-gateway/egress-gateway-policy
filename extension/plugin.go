package extension

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/runtime"
	"github.com/open-policy-agent/opa/v1/storage"
)

const PluginName = "egress_gateway_workload"

// DecisionPath is the Envoy plugin path exported by bundle.BuildExecution.
const DecisionPath = "egress_gateway/workload/authorization/allow"

var registerOnce sync.Once

// OPA passes the manager's runtime information term to its evaluators, including
// the upstream Envoy plugin. Keying by that term isolates in-process runtimes
// without a process-wide current policy or a policy-controlled instance ID.
var instances sync.Map // *ast.Term -> *policyPlugin

// Register installs the OPA factory and builtins. Call before creating runtimes.
// Configure plugins.egress_gateway_workload with Config and load an execution
// bundle through ordinary OPA paths or bundle services.
func Register() {
	registerOnce.Do(func() {
		rego.RegisterBuiltin2(inspectDeclaration, inspect)
		rego.RegisterBuiltin1(acceptDeclaration, accepts)
		runtime.RegisterPlugin(PluginName, factory{})
	})
}

type factory struct{}

func (factory) Validate(_ *plugins.Manager, raw []byte) (any, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing plugin configuration")
	}
	return loadConfig(c)
}

func (factory) New(m *plugins.Manager, config any) plugins.Plugin {
	p := &policyPlugin{manager: m, supply: config.(*snapshot)}
	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	return p
}

type policyPlugin struct {
	manager *plugins.Manager
	trigger storage.TriggerHandle
	mu      sync.Mutex
	supply  *snapshot
	policy  ast.Value
	adapter *adapter
	err     error
}

func (p *policyPlugin) Start(ctx context.Context) error {
	instances.Store(p.manager.Info, p)
	err := storage.Txn(ctx, p.manager.Store, storage.WriteParams, func(txn storage.Transaction) error {
		var err error
		p.trigger, err = p.manager.Store.Register(ctx, txn, storage.TriggerConfig{OnCommit: p.onCommit})
		if err != nil {
			return err
		}
		p.onCommit(ctx, txn, storage.TriggerEvent{})
		return nil
	})
	if err != nil {
		instances.Delete(p.manager.Info)
	}
	return err
}

func (p *policyPlugin) Stop(ctx context.Context) {
	instances.Delete(p.manager.Info)
	if p.trigger != nil {
		_ = storage.Txn(ctx, p.manager.Store, storage.WriteParams, func(txn storage.Transaction) error { p.trigger.Unregister(ctx, txn); return nil })
	}
}

func (p *policyPlugin) Reconfigure(ctx context.Context, config any) {
	p.mu.Lock()
	p.supply, p.policy, p.adapter, p.err = config.(*snapshot), nil, nil, nil
	p.mu.Unlock()
	_ = storage.Txn(ctx, p.manager.Store, storage.TransactionParams{}, func(txn storage.Transaction) error { p.onCommit(ctx, txn, storage.TriggerEvent{}); return nil })
}

func (p *policyPlugin) onCommit(ctx context.Context, txn storage.Transaction, event storage.TriggerEvent) {
	value, err := p.manager.Store.Read(ctx, txn, storage.Path{"egress_gateway", "workload", "config"})
	compiler := plugins.GetCompilerOnContext(event.Context)
	if compiler == nil {
		compiler = p.manager.GetCompiler()
	}
	if err == nil && (len(compiler.GetRulesExact(ast.MustParseRef("data.egress_gateway.workload.authorization.allow"))) == 0 || len(compiler.GetRulesExact(ast.MustParseRef(workload.DecisionQuery))) == 0) {
		err = fmt.Errorf("missing workload execution entry point")
	}
	if err == nil {
		var v ast.Value
		v, err = ast.InterfaceToValue(value)
		if err == nil {
			_, err = p.forPolicy(v)
		}
	}
	status := &plugins.Status{State: plugins.StateOK}
	if err != nil {
		status.State, status.Message = plugins.StateNotReady, err.Error()
	}
	p.manager.UpdatePluginStatus(PluginName, status)
}

func (p *policyPlugin) forPolicy(value ast.Value) (*adapter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.policy != nil && p.policy.Compare(value) == 0 {
		return p.adapter, p.err
	}
	a, err := p.prepare(value)
	p.policy, p.adapter, p.err = value, a, err
	return a, err
}

func (p *policyPlugin) prepare(value ast.Value) (*adapter, error) {
	data, err := ast.JSON(value)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var config struct {
		Version          string           `json:"version"`
		ExtensionVersion string           `json:"extensionVersion"`
		Policy           *workload.Policy `json:"policy"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&config); err != nil {
		return nil, err
	}
	if config.Version != workload.Version || config.ExtensionVersion != "v1" || config.Policy == nil || config.Policy.HostDenylist == nil || config.Policy.RequestConstraints == nil {
		return nil, fmt.Errorf("missing or incompatible workload config")
	}
	policy := *config.Policy
	if len(policy.HostDenylist) == 0 {
		policy.HostDenylist = nil
	}
	if len(policy.RequestConstraints) == 0 {
		policy.RequestConstraints = nil
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	s := &snapshot{Policy: policy, Runtime: p.supply.Runtime, Descriptors: p.supply.Descriptors}
	if err := s.validateDependencies(); err != nil {
		return nil, err
	}
	return newAdapter(s, s.Runtime.Role), nil
}
