//go:build !with_ebpf

package listener

import (
	"strings"
	"testing"
)

// Throwaway verification: without the with_ebpf tag the listener
// still parses, but Listen refuses with a clear message.
func TestEbpfListenerStubRefuses(t *testing.T) {
	l, err := ParseListener(map[string]any{"name": "ebpf-in", "type": "ebpf", "port": 15361})
	if err != nil {
		t.Fatalf("ParseListener(ebpf): %v", err)
	}
	err = l.Listen(nil)
	if err == nil || !strings.Contains(err.Error(), "not included in this build") {
		t.Fatalf("Listen error = %v, want the not-included message", err)
	}
}
