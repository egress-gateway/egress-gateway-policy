package workload_test

import (
	"github.com/egress-gateway/egress-gateway-policy/workload"
	"testing"
)

func TestDecodeDecision(t *testing.T) {
	for _, raw := range []string{
		`{"version":"v1","allowed":true,"code":"pass","violations":[]}`,
		`{"version":"v1","allowed":false,"code":"deny","violations":["hostDenylist"]}`,
		`{"version":"v1","allowed":false,"code":"invalid_input","violations":[]}`,
		`{"version":"v1","allowed":false,"code":"invalid_policy","violations":[]}`,
	} {
		if _, err := workload.DecodeDecision([]byte(raw)); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`null`, `{}`, `[]`, `true`, `{"allowed":true}`,
		`{"version":"v2","allowed":true,"code":"pass","violations":[]}`,
		`{"version":"v1","allowed":null,"code":"pass","violations":[]}`,
		`{"version":"v1","allowed":false,"code":"pass","violations":[]}`,
		`{"version":"v1","allowed":true,"code":"deny","violations":["hostDenylist"]}`,
		`{"version":"v1","allowed":false,"code":"deny","violations":[]}`,
		`{"version":"v1","allowed":false,"code":"deny","violations":[""]}`,
		`{"version":"v1","allowed":true,"code":"invalid_input","violations":[]}`,
		`{"version":"v1","allowed":true,"code":"allow","violations":[]}`,
		`{"version":"v1","allowed":true,"code":"pass","violations":null}`,
		`{"version":"v1","allowed":true,"code":"pass","violations":[],"extra":true}`,
		`{"version":"v1","allowed":false,"allowed":true,"code":"pass","violations":[]}`,
		`{"version":"v1","allowed":true,"code":"pass","violations":[]} {}`,
	} {
		if d, err := workload.DecodeDecision([]byte(raw)); err == nil || d.Allowed {
			t.Fatalf("accepted malformed decision %s: %+v, %v", raw, d, err)
		}
	}
}
