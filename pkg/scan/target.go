package scan

// ScanTarget is a marker interface for typed scan inputs.
type ScanTarget interface {
	ScanKind() string
}

// TLSTarget carries TLS scan input (endpoint URL).
type TLSTarget struct {
	Endpoint string
}

// ScanKind implements ScanTarget.
func (*TLSTarget) ScanKind() string { return KindTLS }
