package listener

import (
	"testing"

	IN "github.com/metacubex/mihomo/listener/inbound"
)

// Throwaway verification: the "ebpf" listener type is registered,
// its options decode from a config mapping, and its name/port are
// honored. Does NOT call Listen (no datapath attach in tests).
func TestParseEbpfListener(t *testing.T) {
	mapping := map[string]any{
		"name":       "ebpf-in",
		"type":       "ebpf",
		"port":       15361,
		"dns-listen": "127.0.0.1:1053",
		"local": map[string]any{
			"enabled":                true,
			"dns-mode":               "hijack",
			"bypass-private-address": true,
		},
		"shared": map[string]any{
			"enabled":                true,
			"dns-mode":               "hijack",
			"interface":              []any{"wlan1"},
			"bypass-private-address": true,
		},
	}
	l, err := ParseListener(mapping)
	if err != nil {
		t.Fatalf("ParseListener(ebpf): %v", err)
	}
	if l.Name() != "ebpf-in" {
		t.Fatalf("name = %q, want ebpf-in", l.Name())
	}
	if l.RawAddress() != "0.0.0.0:15361" {
		t.Fatalf("raw address = %q, want 0.0.0.0:15361", l.RawAddress())
	}
	opt, ok := l.Config().(*IN.EbpfOption)
	if !ok {
		t.Fatalf("config type = %T, want *IN.EbpfOption", l.Config())
	}
	if opt.DNSListen != "127.0.0.1:1053" {
		t.Fatalf("dns-listen = %q", opt.DNSListen)
	}
	if opt.Local.Enabled == nil || !*opt.Local.Enabled {
		t.Fatalf("local.enabled not decoded as true: %v", opt.Local.Enabled)
	}
	if opt.Local.DNSMode != "hijack" {
		t.Fatalf("local.dns-mode = %q", opt.Local.DNSMode)
	}
	if opt.Local.BypassPrivateAddress == nil || !*opt.Local.BypassPrivateAddress {
		t.Fatalf("local.bypass-private-address not decoded as true")
	}
	if len(opt.Shared.Interface) != 1 || opt.Shared.Interface[0] != "wlan1" {
		t.Fatalf("shared.interface = %v", opt.Shared.Interface)
	}
	// Equal must recognize an identical mapping (hot-reload diffing).
	l2, err := ParseListener(mapping)
	if err != nil {
		t.Fatalf("ParseListener(ebpf) #2: %v", err)
	}
	if !l.Config().Equal(l2.Config()) {
		t.Fatal("identical ebpf options must compare Equal")
	}
}
