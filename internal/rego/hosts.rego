package egress_gateway.workload

import rego.v1
import data.egress_gateway.workload.config

host_matches(matcher, host) if {
	matcher.type == "Exact"
	host == matcher.value
}

host_matches(matcher, host) if {
	matcher.type == "DomainSuffix"
	host == matcher.value
}

host_matches(matcher, host) if {
	matcher.type == "DomainSuffix"
	endswith(host, concat("", [".", matcher.value]))
}

valid_matcher(matcher) if {
	is_object(matcher)
	matcher.type in {"Exact", "DomainSuffix"}
	valid_dns(matcher.value)
}

violations contains "hostDenylist" if {
	some matcher in config.policy.hostDenylist
	host_matches(matcher, input.host)
}
