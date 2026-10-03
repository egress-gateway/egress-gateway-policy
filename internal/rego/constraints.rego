package egress_gateway.workload

import rego.v1
import data.egress_gateway.workload.config

host_selected(constraint) if {
	some matcher in constraint.match.hosts
	host_matches(matcher, input.host)
}

dimension_matches(selector, field, value) if {
	object.get(selector, field, null) == null
}

dimension_matches(selector, field, value) if {
	value in selector[field]
}

scope_matches(constraint) if {
	host_selected(constraint)
	input.protocol in {"HTTP", "GRPC"}
	is_object(input.http)
	dimension_matches(constraint.match.http, "methods", input.http.method)
	dimension_matches(constraint.match.http, "paths", input.http.path)
}

scope_matches(constraint) if {
	host_selected(constraint)
	input.protocol == "GRPC"
	input.grpc.service == constraint.match.grpc.service
	dimension_matches(constraint.match.grpc, "methods", input.grpc.method)
}

scope_unavailable(constraint) if {
	host_selected(constraint)
	input.protocol == "Unknown"
}

scope_unavailable(constraint) if {
	host_selected(constraint)
	constraint.match.http
	input.protocol in {"HTTP", "GRPC"}
	object.get(input, "http", null) == null
}

scope_unavailable(constraint) if {
	host_selected(constraint)
	constraint.match.grpc
	input.protocol == "GRPC"
	object.get(input, "grpc", null) == null
}

violations contains concat("", ["requestConstraints/", constraint.name]) if {
	some constraint in config.policy.requestConstraints
	scope_unavailable(constraint)
}

violations contains concat("", ["requestConstraints/", constraint.name]) if {
	some constraint in config.policy.requestConstraints
	scope_matches(constraint)
	not constraint_passes(constraint)
}

constraint_passes(constraint) if {
	decode_ready(constraint)
	every requirement in constraint.require { requirement_passes(constraint, requirement) }
}

decode_ready(constraint) if {
	not constraint.decode
}

decode_ready(constraint) if {
	view := payload_view(constraint)
	view.status == "Ready"
}

payload_view(constraint) := view if {
	some view in input.payloads
	view.format == constraint.decode.format
	descriptor_matches(constraint.decode, view)
}

descriptor_matches(decoder, view) if {
	decoder.format == "JSON"
	object.get(view, "descriptorDigest", "") == ""
}

descriptor_matches(decoder, view) if {
	decoder.format == "Protobuf"
	view.descriptorDigest == decoder.descriptorSet.digest
}

selected(constraint, requirement) := [value] if {
	requirement.source == "Payload"
	view := payload_view(constraint)
	view.status == "Ready"
	tokens := [replace(replace(token, "~1", "/"), "~0", "~") |
		token := array.slice(split(requirement.pointer, "/"), 1, count(split(requirement.pointer, "/")))[_]]
	walk(view.value, [path, value])
	count(path) == count(tokens)
	every index, token in tokens { sprintf("%v", [path[index]]) == token }
}

selected(constraint, requirement) := values if {
	requirement.source == "Header"
	values := input.http.headers[requirement.name]
}

selected(constraint, requirement) := values if {
	requirement.source == "Query"
	values := input.http.query[requirement.name]
}

selected(constraint, requirement) := values if {
	requirement.source == "GRPCMetadata"
	values := input.grpc.metadata[requirement.name]
}

requirement_passes(constraint, requirement) if {
	values := selected(constraint, requirement)
	is_array(values)
	count(values) > 0
	every value in values { value_passes(requirement, value) }
}

value_passes(requirement, value) if {
	requirement.operator == "Exists"
	value != null
}

value_passes(requirement, value) if {
	requirement.operator == "In"
	is_string(value)
	value in requirement.values
}

value_passes(requirement, value) if {
	requirement.operator == "NotIn"
	is_string(value)
	not value in requirement.values
}
