package policy

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// BuiltinYAML is the documented default RBAC policy used when AUTH_POLICY_FILE
// is missing. Empty/missing files must not silently become deny-all.
const BuiltinYAML = `roles:
  admin:
    permissions: ["*"]
  manager:
    permissions:
      - "media.*"
      - "storage.*"
      - "modules.read"
      - "modules.manage"
  user:
    permissions:
      - "media.request"
      - "media.view"
      - "media.search"
  viewer:
    permissions:
      - "media.view"
      - "media.search"
  module:
    permissions: ["*"]
`

// Builtin returns the documented default RBAC policy.
func Builtin() *Policy {
	p, err := Parse([]byte(BuiltinYAML))
	if err != nil {
		panic("policy.Builtin: " + err.Error())
	}
	return p
}

// Config is the top-level RBAC policy configuration.
type Config struct {
	Roles map[string]RoleConfig `yaml:"roles"`
}

// RoleConfig defines the permissions for a role.
type RoleConfig struct {
	Permissions []string `yaml:"permissions"`
}

// Policy evaluates authorization decisions against a loaded RBAC config.
type Policy struct {
	mu    sync.RWMutex
	roles map[string][]string // role → expanded permissions
}

// Load reads a YAML policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML policy data.
func Parse(data []byte) (*Policy, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	p := &Policy{roles: make(map[string][]string)}
	for name, rc := range cfg.Roles {
		p.roles[name] = rc.Permissions
	}
	return p, nil
}

// IsAllowed checks if a user with the given roles can perform an action on a resource.
// Permission matching rules:
//   - "*" matches anything (superuser)
//   - "resource.*" matches any action on the resource
//   - "resource.action" matches a specific resource+action
//   - "." matches nothing (empty permission)
func (p *Policy) IsAllowed(userRoles []string, action, resource string) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, userRole := range userRoles {
		perms, ok := p.roles[userRole]
		if !ok {
			continue
		}
		for _, perm := range perms {
			if perm == "*" {
				return true, ""
			}
			if matchPermission(perm, action, resource) {
				return true, ""
			}
		}
	}
	return false, "insufficient permissions"
}

// RoleCount returns the number of defined roles.
func (p *Policy) RoleCount() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.roles)
}

// Replace atomically replaces the policy data. Used for SIGHUP reload.
func (p *Policy) Replace(src *Policy) {
	src.mu.RLock()
	roles := make(map[string][]string, len(src.roles))
	for k, v := range src.roles {
		perms := make([]string, len(v))
		copy(perms, v)
		roles[k] = perms
	}
	src.mu.RUnlock()

	p.mu.Lock()
	p.roles = roles
	p.mu.Unlock()
}

// matchPermission checks if a permission grants an action on a resource.
// Permission format: "resource.action", "resource.*", or "*"
func matchPermission(perm, action, resource string) bool {
	if perm == "*" {
		return true
	}
	// Split on the first dot.
	dot := strings.IndexByte(perm, '.')
	if dot < 0 {
		return perm == resource && action == "*"
	}
	permResource := perm[:dot]
	permAction := perm[dot+1:]

	if permResource != "*" && permResource != resource {
		return false
	}
	if permAction != "*" && permAction != action {
		return false
	}
	return true
}
