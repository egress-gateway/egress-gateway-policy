package egress_gateway.workload

import rego.v1
import data.egress_gateway.workload.config

decision := {"version": "v1", "allowed": false, "code": "invalid_policy", "violations": []} if {
	not valid_config
} else := {"version": "v1", "allowed": false, "code": "invalid_input", "violations": []} if {
	not valid_input
} else := {"version": "v1", "allowed": false, "code": "deny", "violations": sort(violations)} if {
	count(violations) > 0
} else := {"version": "v1", "allowed": true, "code": "pass", "violations": []}

valid_config if {
	config.version == "v1"
	is_object(config.policy)
	is_array(config.policy.hostDenylist)
	is_array(config.policy.requestConstraints)
	every matcher in config.policy.hostDenylist { valid_matcher(matcher) }
	every c in config.policy.requestConstraints { valid_constraint(c) }
	names := {c.name | some c in config.policy.requestConstraints}
	count(names) == count(config.policy.requestConstraints)
}

valid_input if {
	is_object(input)
	input.version == "v1"
	valid_target(input.host)
	input.protocol in {"HTTP", "GRPC", "Other", "Unknown"}
	valid_http
	valid_grpc
	valid_payloads
}
