package scan

import "sync"

var (
	registry   = make(map[string]Plugin)
	registryMu sync.RWMutex
)

// Register registers a plugin by kind.
func Register(p Plugin) {
	registryMu.Lock()
	defer registryMu.Unlock()
	d := p.Descriptor()
	registry[d.Kind] = p
}

// Get returns the plugin for the given kind, or nil.
func Get(kind string) Plugin {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[kind]
}
