package egress_gateway.workload

import rego.v1

# Authoring validation belongs to Go. These guards protect evaluation against
# missing data and malformed normalized facts at the bundle/adapter boundary.
valid_constraint(c) if {
	is_object(c)
	is_string(c.name)
	count(c.name) > 0
	is_object(c.match)
	is_array(c.match.hosts)
	count(c.match.hosts) > 0
	every h in c.match.hosts { valid_matcher(h) }
	valid_scope(c.match)
	valid_decoder(c)
	is_array(c.require)
	count(c.require) > 0
	every r in c.require { valid_requirement(c, r) }
}

valid_scope(m) if {
	is_object(m.http)
	object.get(m, "grpc", null) == null
	optional_strings(m.http, "methods")
	optional_strings(m.http, "paths")
}

valid_scope(m) if {
	is_object(m.grpc)
	object.get(m, "http", null) == null
	is_string(m.grpc.service)
	count(m.grpc.service) > 0
	optional_strings(m.grpc, "methods")
}

optional_strings(obj, key) if { not key in object.keys(obj) }
optional_strings(obj, key) if { nonempty_strings(obj[key]) }

nonempty_strings(values) if {
	is_array(values)
	count(values) > 0
	every value in values { is_string(value) }
}

valid_decoder(c) if { not "decode" in object.keys(c) }
valid_decoder(c) if {
	is_object(c.decode)
	c.decode.format == "JSON"
	is_object(c.match.http)
	not "descriptorSet" in object.keys(c.decode)
}
valid_decoder(c) if {
	is_object(c.decode)
	c.decode.format == "Protobuf"
	is_object(c.match.grpc)
	is_object(c.decode.descriptorSet)
	is_string(c.decode.descriptorSet.url)
	startswith(c.decode.descriptorSet.url, "https://")
	valid_digest(c.decode.descriptorSet.digest)
}

valid_digest(value) if {
	is_string(value)
	regex.match(`^sha256:[0-9a-f]{64}$`, value)
}

valid_requirement(c, r) if {
	is_object(r)
	valid_selector(c, r)
	valid_operator(r)
}
valid_selector(c, r) if {
	r.source == "Payload"
	is_object(c.decode)
	is_string(r.pointer)
	regex.match(`^(/([^~/]|~[01])*)+$`, r.pointer)
	not "name" in object.keys(r)
}
valid_selector(c, r) if {
	r.source in {"Header", "Query"}
	is_object(c.match.http)
	is_string(r.name)
	count(r.name) > 0
	not "pointer" in object.keys(r)
}
valid_selector(c, r) if {
	r.source == "GRPCMetadata"
	is_object(c.match.grpc)
	is_string(r.name)
	count(r.name) > 0
	not "pointer" in object.keys(r)
}
valid_operator(r) if {
	r.operator in {"In", "NotIn"}
	nonempty_strings(r.values)
}
valid_operator(r) if {
	r.operator == "Exists"
	not "values" in object.keys(r)
}

valid_dns(value) if {
	is_string(value)
	count(value) <= 253
	regex.match(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`, value)
	not regex.match(`^[0-9]+(\.[0-9]+){3}$`, value)
}
valid_target(value) if { valid_dns(value) }
valid_target(value) if {
	is_string(value)
	not contains(value, "/")
	net.cidr_is_valid(concat("", [value, "/32"]))
}
valid_target(value) if {
	is_string(value)
	not contains(value, "/")
	net.cidr_is_valid(concat("", [value, "/128"]))
}

valid_http if { object.get(input, "http", null) == null }
valid_http if {
	h := input.http
	is_object(h)
	input.protocol in {"HTTP", "GRPC"}
	is_string(h.method)
	regex.match("^[!#$%&'*+.^_`|~0-9A-Z-]+$", h.method)
	is_string(h.path)
	startswith(h.path, "/")
	not regex.match(`[?#\s]`, h.path)
	valid_attributes(object.get(h, "headers", null), "header")
	valid_attributes(object.get(h, "query", null), "query")
}
valid_grpc if { object.get(input, "grpc", null) == null }
valid_grpc if {
	g := input.grpc
	is_object(g)
	input.protocol == "GRPC"
	is_string(g.service)
	regex.match(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`, g.service)
	is_string(g.method)
	regex.match(`^[A-Za-z_][A-Za-z0-9_]*$`, g.method)
	valid_attributes(object.get(g, "metadata", null), "metadata")
}
valid_attributes(values, kind) if { values == null }
valid_attributes(values, kind) if {
	is_object(values)
	every key, entries in values {
		valid_attribute_key(key, kind)
		nonempty_strings(entries)
	}
}
valid_attribute_key(key, kind) if {
	kind == "header"
	regex.match("^[!#$%&'*+.^_`|~0-9a-z-]+$", key)
}
valid_attribute_key(key, kind) if { kind == "query" }
valid_attribute_key(key, kind) if {
	kind == "metadata"
	regex.match(`^[0-9a-z_.-]+$`, key)
	not endswith(key, "-bin")
}

valid_payloads if {
	views := object.get(input, "payloads", [])
	is_array(views)
	every v in views { valid_view(v) }
	identities := {[v.format, object.get(v, "descriptorDigest", "")] | some v in views}
	count(identities) == count(views)
}
valid_view(v) if {
	is_object(v)
	valid_view_format(v)
	v.status in {"Ready", "Unavailable", "Invalid", "Truncated", "Unsupported"}
	"value" in object.keys(v)
}
valid_view_format(v) if {
	v.format == "JSON"
	object.get(v, "descriptorDigest", "") == ""
}
valid_view_format(v) if {
	v.format == "Protobuf"
	valid_digest(v.descriptorDigest)
}
