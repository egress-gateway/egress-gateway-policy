package workload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type DecisionCode string

const (
	Pass          DecisionCode = "pass"
	Deny          DecisionCode = "deny"
	InvalidInput  DecisionCode = "invalid_input"
	InvalidPolicy DecisionCode = "invalid_policy"
)

// Decision reports only the workload baseline, never final egress permission.
// OPA evaluation errors and undefined results are separate caller errors. Use
// DecodeDecision on the single query expression value before trusting Allowed.
type Decision struct {
	Version    string       `json:"version"`
	Allowed    bool         `json:"allowed"`
	Code       DecisionCode `json:"code"`
	Violations []string     `json:"violations"`
}

// DecodeDecision rejects malformed, ambiguous or incompatible decision values.
// It accepts the query expression value, not the OPA REST/result-set envelope.
func DecodeDecision(data []byte) (Decision, error) {
	var zero Decision
	d := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSON(d); err != nil {
		return zero, fmt.Errorf("decision: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return zero, fmt.Errorf("decision: trailing JSON data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return zero, fmt.Errorf("decision: %w", err)
	}
	if len(fields) != 4 {
		return zero, fmt.Errorf("decision: expected version, allowed, code and violations")
	}
	for _, key := range []string{"version", "allowed", "code", "violations"} {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return zero, fmt.Errorf("decision: missing or null %s", key)
		}
	}
	var result Decision
	if err := json.Unmarshal(data, &result); err != nil {
		return zero, fmt.Errorf("decision: %w", err)
	}
	if result.Version != Version {
		return zero, fmt.Errorf("decision: unsupported version")
	}
	switch result.Code {
	case Pass:
		if !result.Allowed || len(result.Violations) != 0 {
			return zero, fmt.Errorf("decision: inconsistent pass")
		}
	case Deny:
		if result.Allowed || len(result.Violations) == 0 {
			return zero, fmt.Errorf("decision: inconsistent deny")
		}
	case InvalidInput, InvalidPolicy:
		if result.Allowed || len(result.Violations) != 0 {
			return zero, fmt.Errorf("decision: inconsistent invalid result")
		}
	default:
		return zero, fmt.Errorf("decision: unsupported code")
	}
	for _, v := range result.Violations {
		if v == "" {
			return zero, fmt.Errorf("decision: empty violation identifier")
		}
	}
	return result, nil
}

// Standard JSON decoding accepts duplicate object keys; a security decision
// must have one unambiguous value for each field.
func checkJSON(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid object key")
			}
			seen[name] = true
			if err := checkJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case json.Delim('['):
		for d.More() {
			if err := checkJSON(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	return nil
}
