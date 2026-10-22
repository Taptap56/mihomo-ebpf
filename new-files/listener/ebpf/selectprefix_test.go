//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"golang.org/x/sys/unix"
)

// Reproduces the phone failure of 2026-10-20 20:09
// ("redirect prefix address family mismatch: 127.128.0.0/9"):
// the family argument must be unix.AF_INET / unix.AF_INET6.
func TestSelectRedirectPrefixFamilies(t *testing.T) {
	prefix, err := commonEBPF.SelectRedirectPrefix(unix.AF_INET, redirectIPv4Candidates, nil)
	if err != nil {
		t.Fatalf("IPv4 select: %v", err)
	}
	if prefix.String() != "127.128.0.0/9" {
		t.Fatalf("IPv4 prefix = %v, want 127.128.0.0/9", prefix)
	}
	prefix, err = commonEBPF.SelectRedirectPrefix(unix.AF_INET6, redirectIPv6Candidates, nil)
	if err != nil {
		t.Fatalf("IPv6 select: %v", err)
	}
	if !prefix.IsValid() {
		t.Fatal("IPv6 prefix invalid")
	}
	t.Logf("IPv6 prefix = %v", prefix)
}

// The phone failure of 2026-10-20 20:24: the Manager passed the
// device's interface prefixes as exclusions, so the loopback
// prefix rejected both candidates. The Manager's own selection
// path must succeed with no consumer-side exclusions.
func TestManagerSelectRedirectPrefixes(t *testing.T) {
	manager := &Manager{}
	if err := manager.selectRedirectPrefixes(); err != nil {
		t.Fatalf("selectRedirectPrefixes: %v", err)
	}
	if manager.redirectIPv4.String() != "127.128.0.0/9" {
		t.Fatalf("redirectIPv4 = %v, want 127.128.0.0/9", manager.redirectIPv4)
	}
	if !manager.redirectIPv6.IsValid() {
		t.Fatal("redirectIPv6 invalid")
	}
}
