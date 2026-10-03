package extension

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/egress-gateway/egress-gateway-policy/workload"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Config is trusted OPA plugin configuration, independent of the bundle's rules.
// Descriptor bytes are read only during plugin configuration. URL identifies
// staged bytes; the extension never retrieves it over the network.
type Config struct {
	Role         string           `json:"role"`
	Descriptors  []DescriptorFile `json:"descriptors,omitempty"`
	AllowedPeers []string         `json:"allowedPeers,omitempty"`
}

type DescriptorFile struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
	Path   string `json:"path"`
}

type snapshot struct {
	Policy      workload.Policy
	Runtime     Config
	Descriptors map[workload.ArtifactRef]*protoregistry.Files
}

func loadConfig(c Config) (*snapshot, error) {
	if c.Role != "workload" && c.Role != "egress" {
		return nil, fmt.Errorf("role must be workload or egress")
	}
	if c.Role == "egress" && len(c.AllowedPeers) == 0 {
		return nil, fmt.Errorf("egress requires allowedPeers")
	}
	for _, peer := range c.AllowedPeers {
		u, err := url.Parse(peer)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(peer, "* \t\r\n") || u.Path == "" {
			return nil, fmt.Errorf("allowedPeers must contain exact SPIFFE identities")
		}
	}
	s := &snapshot{Runtime: c, Descriptors: make(map[workload.ArtifactRef]*protoregistry.Files)}
	for _, d := range c.Descriptors {
		ref := workload.ArtifactRef{URL: d.URL, Digest: d.Digest}
		if !filepath.IsAbs(d.Path) || filepath.Clean(d.Path) != d.Path || d.Path == "/" || d.URL == "" {
			return nil, fmt.Errorf("descriptor requires URL and clean absolute path")
		}
		if _, exists := s.Descriptors[ref]; exists {
			return nil, fmt.Errorf("duplicate descriptor reference")
		}
		raw, err := os.ReadFile(d.Path)
		if err != nil {
			return nil, fmt.Errorf("read descriptor: %w", err)
		}
		if fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != d.Digest {
			return nil, fmt.Errorf("descriptor digest mismatch")
		}
		var set descriptorpb.FileDescriptorSet
		if err := proto.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("invalid descriptor set: %w", err)
		}
		files, err := protodesc.NewFiles(&set)
		if err != nil {
			return nil, fmt.Errorf("invalid descriptor definitions or imports: %w", err)
		}
		s.Descriptors[ref] = files
	}
	return s, nil
}

func (s *snapshot) validateDependencies() error {
	for _, c := range s.Policy.RequestConstraints {
		if c.Decode == nil || c.Decode.Format != workload.Protobuf {
			continue
		}
		files := s.Descriptors[*c.Decode.DescriptorSet]
		if files == nil {
			return fmt.Errorf("constraint %s: descriptor is not staged", c.Name)
		}
		d, err := files.FindDescriptorByName(protoreflect.FullName(c.Match.GRPC.Service))
		if err != nil {
			return fmt.Errorf("constraint %s: descriptor service unavailable", c.Name)
		}
		service, ok := d.(protoreflect.ServiceDescriptor)
		if !ok {
			return fmt.Errorf("constraint %s: descriptor name is not a service", c.Name)
		}
		for _, method := range c.Match.GRPC.Methods {
			if service.Methods().ByName(protoreflect.Name(method)) == nil {
				return fmt.Errorf("constraint %s: descriptor method unavailable", c.Name)
			}
		}
	}
	return nil
}
