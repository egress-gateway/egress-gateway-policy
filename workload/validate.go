package workload

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	dnsName      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)
	ipv4Name     = regexp.MustCompile(`^[0-9]+(\.[0-9]+){3}$`)
	ruleName     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	httpMethod   = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Z-]+$")
	headerName   = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]+$")
	metadataName = regexp.MustCompile(`^[0-9a-z_.-]+$`)
	grpcService  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	grpcMethod   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	pointer      = regexp.MustCompile(`^(/([^~/]|~[01])*)+$`)
	digest       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Validate rejects invalid or ambiguous rule configurations. It performs no I/O.
func (p Policy) Validate() error {
	if err := validateHosts("hostDenylist", p.HostDenylist, 256, true); err != nil {
		return err
	}
	if err := listSize("requestConstraints", len(p.RequestConstraints), p.RequestConstraints == nil, 128, true); err != nil {
		return err
	}
	names := make(map[string]bool)
	for i, c := range p.RequestConstraints {
		path := fmt.Sprintf("requestConstraints[%d]", i)
		if !bounded(c.Name, 1, 63) || !ruleName.MatchString(c.Name) {
			return invalid(path+".name", "must be a DNS-label-style identifier of at most 63 characters")
		}
		if names[c.Name] {
			return invalid(path+".name", "duplicate constraint name")
		}
		names[c.Name] = true
		if err := validateConstraint(path, c); err != nil {
			return err
		}
	}
	return nil
}

func validateConstraint(path string, c Constraint) error {
	if err := validateHosts(path+".match.hosts", c.Match.Hosts, 32, false); err != nil {
		return err
	}
	if (c.Match.HTTP == nil) == (c.Match.GRPC == nil) {
		return invalid(path+".match", "exactly one of http and grpc is required")
	}
	if h := c.Match.HTTP; h != nil {
		if err := validateStrings(path+".match.http.methods", h.Methods, 16, true, func(s string) bool { return bounded(s, 1, 32) && httpMethod.MatchString(s) }); err != nil {
			return err
		}
		if err := validateStrings(path+".match.http.paths", h.Paths, 64, true, validPath); err != nil {
			return err
		}
	}
	if g := c.Match.GRPC; g != nil {
		if !bounded(g.Service, 1, 256) || !grpcService.MatchString(g.Service) {
			return invalid(path+".match.grpc.service", "invalid fully qualified service name")
		}
		if err := validateStrings(path+".match.grpc.methods", g.Methods, 64, true, func(s string) bool { return bounded(s, 1, 128) && grpcMethod.MatchString(s) }); err != nil {
			return err
		}
	}
	if c.Decode != nil {
		switch c.Decode.Format {
		case JSON:
			if c.Match.HTTP == nil || c.Decode.DescriptorSet != nil {
				return invalid(path+".decode", "JSON requires HTTP scope and forbids descriptorSet")
			}
		case Protobuf:
			if c.Match.GRPC == nil || c.Decode.DescriptorSet == nil {
				return invalid(path+".decode", "Protobuf requires gRPC scope and descriptorSet")
			}
			ref := c.Decode.DescriptorSet
			u, err := url.Parse(ref.URL)
			if err != nil || !bounded(ref.URL, 1, 2048) || strings.IndexFunc(ref.URL, unicode.IsSpace) >= 0 || u.Scheme != "https" || u.Hostname() == "" {
				return invalid(path+".decode.descriptorSet.url", "must be an HTTPS URL with a host")
			}
			if !digest.MatchString(ref.Digest) {
				return invalid(path+".decode.descriptorSet.digest", "must be sha256 followed by 64 lowercase hexadecimal digits")
			}
		default:
			return invalid(path+".decode.format", "unsupported decoder format")
		}
	}
	if err := listSize(path+".require", len(c.Require), c.Require == nil, 32, false); err != nil {
		return err
	}
	for i, r := range c.Require {
		rp := fmt.Sprintf("%s.require[%d]", path, i)
		switch r.Source {
		case Payload:
			if r.Name != nil || r.Pointer == nil || !bounded(*r.Pointer, 1, 512) || !pointer.MatchString(*r.Pointer) {
				return invalid(rp, "Payload requires a nonempty RFC 6901 pointer and forbids name")
			}
			if c.Decode == nil {
				return invalid(rp, "Payload requires decode")
			}
		case Header, Query, GRPCMetadata:
			if r.Pointer != nil || r.Name == nil || !bounded(*r.Name, 1, 256) {
				return invalid(rp, "attribute source requires a nonempty name and forbids pointer")
			}
			if r.Source == GRPCMetadata {
				if c.Match.GRPC == nil || !metadataName.MatchString(*r.Name) || strings.HasSuffix(*r.Name, "-bin") {
					return invalid(rp, "GRPCMetadata requires gRPC scope and a lowercase text metadata key")
				}
			} else {
				if c.Match.HTTP == nil {
					return invalid(rp, "Header and Query require HTTP scope")
				}
				if r.Source == Header && !headerName.MatchString(*r.Name) {
					return invalid(rp+".name", "must be a lowercase HTTP header token")
				}
			}
		default:
			return invalid(rp+".source", "unsupported selector source")
		}
		switch r.Operator {
		case In, NotIn:
			if err := validateStrings(rp+".values", r.Values, 128, false, func(s string) bool { return bounded(s, 0, 256) }); err != nil {
				return err
			}
		case Exists:
			if r.Values != nil {
				return invalid(rp+".values", "Exists forbids values")
			}
		default:
			return invalid(rp+".operator", "unsupported operator")
		}
	}
	return nil
}

func validateHosts(path string, hosts []HostMatcher, max int, optional bool) error {
	if err := listSize(path, len(hosts), hosts == nil, max, optional); err != nil {
		return err
	}
	seen := make(map[HostMatcher]bool)
	for i, h := range hosts {
		hp := fmt.Sprintf("%s[%d]", path, i)
		if h.Type != Exact && h.Type != DomainSuffix {
			return invalid(hp+".type", "unsupported host matcher")
		}
		if !bounded(h.Value, 1, 253) || !dnsName.MatchString(h.Value) || ipv4Name.MatchString(h.Value) {
			return invalid(hp+".value", "must be a lowercase ASCII DNS name without a port, trailing dot, wildcard or IP literal")
		}
		if seen[h] {
			return invalid(hp, "duplicate host matcher")
		}
		seen[h] = true
	}
	return nil
}

func validateStrings(path string, values []string, max int, optional bool, valid func(string) bool) error {
	if err := listSize(path, len(values), values == nil, max, optional); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for i, value := range values {
		if !valid(value) {
			return invalid(fmt.Sprintf("%s[%d]", path, i), "invalid value")
		}
		if seen[value] {
			return invalid(fmt.Sprintf("%s[%d]", path, i), "duplicate set value")
		}
		seen[value] = true
	}
	return nil
}

func listSize(path string, length int, absent bool, max int, optional bool) error {
	if optional && absent {
		return nil
	}
	if length < 1 || length > max {
		return invalid(path, fmt.Sprintf("requires 1..%d entries when present", max))
	}
	return nil
}

func bounded(s string, min, max int) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= min && n <= max
}

func validPath(s string) bool {
	return bounded(s, 1, 2048) && strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "?#") && strings.IndexFunc(s, unicode.IsSpace) < 0
}

func invalid(path, message string) error { return fmt.Errorf("%s: %s", path, message) }
