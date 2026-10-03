package workload

// Policy is the workload baseline. Nil optional slices mean omitted; non-nil
// empty slices are invalid. omitzero preserves this distinction on the wire.
type Policy struct {
	HostDenylist       []HostMatcher `json:"hostDenylist,omitzero"`
	RequestConstraints []Constraint  `json:"requestConstraints,omitzero"`
}

type HostMatchType string

const (
	Exact        HostMatchType = "Exact"
	DomainSuffix HostMatchType = "DomainSuffix"
)

type HostMatcher struct {
	Type  HostMatchType `json:"type"`
	Value string        `json:"value"`
}

// Constraint applies every requirement to requests in Match.
type Constraint struct {
	Name    string        `json:"name"`
	Match   Match         `json:"match"`
	Decode  *Decoder      `json:"decode,omitempty"`
	Require []Requirement `json:"require"`
}

// Match selects exactly one protocol. Alternatives in each list are ORed;
// dimensions and all applicable constraints are ANDed.
type Match struct {
	Hosts []HostMatcher `json:"hosts"`
	HTTP  *HTTPMatch    `json:"http,omitempty"`
	GRPC  *GRPCMatch    `json:"grpc,omitempty"`
}

type HTTPMatch struct {
	Methods []string `json:"methods,omitzero"`
	Paths   []string `json:"paths,omitzero"`
}

type GRPCMatch struct {
	Service string   `json:"service"`
	Methods []string `json:"methods,omitzero"`
}

type Format string

const (
	JSON     Format = "JSON"
	Protobuf Format = "Protobuf"
)

// Decoder declares the inspection needed by a constraint. Policy does not
// perform wire decoding or fetch artifacts.
type Decoder struct {
	Format        Format       `json:"format"`
	DescriptorSet *ArtifactRef `json:"descriptorSet,omitempty"`
}

type ArtifactRef struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
}

type Source string

const (
	Payload      Source = "Payload"
	Header       Source = "Header"
	Query        Source = "Query"
	GRPCMetadata Source = "GRPCMetadata"
)

type Operator string

const (
	In     Operator = "In"
	NotIn  Operator = "NotIn"
	Exists Operator = "Exists"
)

// Requirement selects one payload value or all values of a named attribute.
// Pointer and Name use pointers to distinguish absence from an empty selector.
type Requirement struct {
	Source   Source   `json:"source"`
	Pointer  *string  `json:"pointer,omitempty"`
	Name     *string  `json:"name,omitempty"`
	Operator Operator `json:"operator"`
	Values   []string `json:"values,omitzero"`
}
