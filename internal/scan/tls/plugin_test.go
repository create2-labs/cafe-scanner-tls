package tls

import (
	"testing"

	requestv1 "github.com/create2-labs/cafe-contracts/discovery/scanrequest/v1"
)

func TestPluginSubjectComesFromContract(t *testing.T) {
	if requestv1.SubjectTLSScan != "cafe.discovery.tls.scan" {
		t.Fatalf("fallback = %s", requestv1.SubjectTLSScan)
	}
	if requestv1.SubjectScanRequestedTLS != "scan.requested.tls" {
		t.Fatalf("requested = %s", requestv1.SubjectScanRequestedTLS)
	}

	fallback := NewPlugin(nil, "", "")
	if fallback.Descriptor().Subject != requestv1.SubjectTLSScan {
		t.Fatalf("subject = %s", fallback.Descriptor().Subject)
	}
	overridden := NewPlugin(nil, "", requestv1.SubjectScanRequestedTLS)
	if overridden.Descriptor().Subject != requestv1.SubjectScanRequestedTLS {
		t.Fatalf("subject = %s", overridden.Descriptor().Subject)
	}
}
