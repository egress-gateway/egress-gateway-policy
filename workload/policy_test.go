package workload_test

import (
	"encoding/json"
	"testing"

	"github.com/egress-gateway/egress-gateway-policy/workload"
)

func TestHostPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy workload.Policy
		valid  bool
	}{
		{"empty baseline", workload.Policy{}, true},
		{"explicit empty list", workload.Policy{HostDenylist: []workload.HostMatcher{}}, false},
		{"exact", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "blocked.example"}}}, true},
		{"suffix", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.DomainSuffix, Value: "example.com"}}}, true},
		{"unknown matcher", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: "Allow", Value: "example.com"}}}, false},
		{"uppercase", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "Example.com"}}}, false},
		{"trailing dot", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "example.com."}}}, false},
		{"IP", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "192.0.2.1"}}}, false},
		{"wildcard", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "*.example.com"}}}, false},
		{"duplicate matcher", workload.Policy{HostDenylist: []workload.HostMatcher{{Type: workload.Exact, Value: "a.example"}, {Type: workload.Exact, Value: "a.example"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tc.valid)
			}
		})
	}
}

func TestPolicyJSONPreservesOmittedAndEmptyLists(t *testing.T) {
	for _, tc := range []struct {
		policy workload.Policy
		want   string
	}{
		{workload.Policy{}, `{}`},
		{workload.Policy{HostDenylist: []workload.HostMatcher{}}, `{"hostDenylist":[]}`},
	} {
		got, err := json.Marshal(tc.policy)
		if err != nil || string(got) != tc.want {
			t.Fatalf("Marshal() = %s, %v; want %s", got, err, tc.want)
		}
	}
}
