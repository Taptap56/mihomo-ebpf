//go:build !with_ebpf || !linux && !android

package ebpf

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

// Manager is a stub on platforms without eBPF cgroup/TC support.
type Manager struct{}

// NewManager creates a stub Manager.
func NewManager(cfg LC.Ebpf, tunnel C.Tunnel, name string) *Manager {
	return &Manager{}
}

// Start always fails: the eBPF datapath needs a linux/android
// build with the with_ebpf tag.
func (m *Manager) Start() error {
	return errors.New("ebpf: datapath is not included in this build (needs linux/android with the with_ebpf build tag)")
}

// Close is a no-op.
func (m *Manager) Close() error { return nil }
