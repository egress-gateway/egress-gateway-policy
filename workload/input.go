package workload

// Version identifies the normalized input, decision and bundle-data contract.
const Version = "v1"

// DecisionQuery is the OPA query exported by a generated workload bundle.
const DecisionQuery = "data.egress_gateway.workload.decision"

type Protocol string

const (
	HTTP    Protocol = "HTTP"
	GRPC    Protocol = "GRPC"
	Other   Protocol = "Other"
	Unknown Protocol = "Unknown"
)

// Input is produced by a trusted gateway adapter, never by the application.
// Host is the canonical actual forwarding DNS name or IP, without a port.
// Unknown means protocol inspection is unavailable; Other means positively
// recognized as outside HTTP/gRPC. GRPC can carry both HTTP and GRPC attributes.
type Input struct {
	Version  string        `json:"version"`
	Host     string        `json:"host"`
	Protocol Protocol      `json:"protocol"`
	HTTP     *HTTPRequest  `json:"http,omitempty"`
	GRPC     *GRPCRequest  `json:"grpc,omitempty"`
	Payloads []PayloadView `json:"payloads,omitempty"`
}

// HTTPRequest contains normalized request attributes. A nil attribute map means
// unavailable inspection; an empty non-nil map means inspected with no values.
// Repeated values are preserved. Empty value slices are invalid.
type HTTPRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Query   map[string][]string `json:"query"`
}

type GRPCRequest struct {
	Service  string              `json:"service"`
	Method   string              `json:"method"`
	Metadata map[string][]string `json:"metadata"`
}

type InspectionStatus string

const (
	Ready       InspectionStatus = "Ready"
	Unavailable InspectionStatus = "Unavailable"
	Invalid     InspectionStatus = "Invalid"
	Truncated   InspectionStatus = "Truncated"
	Unsupported InspectionStatus = "Unsupported"
)

// PayloadView is one complete decoded view: JSON or ProtoJSON produced using
// a verified Protobuf descriptor digest. Multiple constraints may use different
// descriptors. There must be at most one view per format/digest pair.
// A Ready Value can legitimately be JSON null; selectors still have to pass.
type PayloadView struct {
	Format           Format           `json:"format"`
	DescriptorDigest string           `json:"descriptorDigest,omitempty"`
	Status           InspectionStatus `json:"status"`
	Value            any              `json:"value"`
}
