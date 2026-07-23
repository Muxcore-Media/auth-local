package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltin(t *testing.T) {
	p := Builtin()
	if p.RoleCount() != 4 {
		t.Fatalf("RoleCount = %d, want 4", p.RoleCount())
	}
	if allowed, _ := p.IsAllowed([]string{"admin"}, "x", "y"); !allowed {
		t.Error("admin should be allowed")
	}
	if allowed, _ := p.IsAllowed([]string{"viewer"}, "view", "media"); !allowed {
		t.Error("viewer should view media")
	}
	if allowed, _ := p.IsAllowed([]string{"viewer"}, "delete", "media"); allowed {
		t.Error("viewer should not delete media")
	}
}

func TestParse_Empty(t *testing.T) {
	p, err := Parse([]byte(`roles: {}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	allowed, _ := p.IsAllowed([]string{"admin"}, "read", "media")
	if allowed {
		t.Error("expected empty policy to deny")
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := Parse([]byte(`{{{`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSuperuser(t *testing.T) {
	p, err := Parse([]byte(`
roles:
  admin:
    permissions: ["*"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if allowed, _ := p.IsAllowed([]string{"admin"}, "anything", "anything"); !allowed {
		t.Error("expected admin to have all permissions")
	}
}

func TestResourceWildcard(t *testing.T) {
	p, err := Parse([]byte(`
roles:
  user:
    permissions: ["media.*"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, action := range []string{"view", "request", "delete"} {
		if allowed, _ := p.IsAllowed([]string{"user"}, action, "media"); !allowed {
			t.Errorf("expected user to have %s on media", action)
		}
	}
	if allowed, _ := p.IsAllowed([]string{"user"}, "view", "storage"); allowed {
		t.Error("expected user to be denied on storage")
	}
}

func TestSpecificPermission(t *testing.T) {
	p, err := Parse([]byte(`
roles:
  viewer:
    permissions: ["media.view"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if allowed, _ := p.IsAllowed([]string{"viewer"}, "view", "media"); !allowed {
		t.Error("expected viewer to have view on media")
	}
	if allowed, _ := p.IsAllowed([]string{"viewer"}, "delete", "media"); allowed {
		t.Error("expected viewer to be denied delete")
	}
}

func TestMultipleRoles(t *testing.T) {
	p, err := Parse([]byte(`
roles:
  user:
    permissions: ["media.view", "media.request"]
  manager:
    permissions: ["media.*"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if allowed, _ := p.IsAllowed([]string{"user"}, "view", "media"); !allowed {
		t.Error("expected user to have view")
	}
	if allowed, _ := p.IsAllowed([]string{"user"}, "delete", "media"); allowed {
		t.Error("expected user to be denied delete")
	}
	if allowed, _ := p.IsAllowed([]string{"manager"}, "delete", "media"); !allowed {
		t.Error("expected manager to have delete")
	}
}

func TestUnknownRole(t *testing.T) {
	p, err := Parse([]byte(`
roles:
  admin:
    permissions: ["*"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if allowed, _ := p.IsAllowed([]string{"nonexistent"}, "view", "media"); allowed {
		t.Error("expected unknown role to be denied")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	os.WriteFile(path, []byte(`
roles:
  admin:
    permissions: ["*"]
`), 0644)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if allowed, _ := p.IsAllowed([]string{"admin"}, "x", "y"); !allowed {
		t.Error("expected loaded policy to work")
	}
}

func TestLoad_NotFound(t *testing.T) {
	_, err := Load("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestReplace(t *testing.T) {
	p, _ := Parse([]byte(`roles: {admin: {permissions: ["*"]}}`))
	p2, _ := Parse([]byte(`roles: {viewer: {permissions: ["media.view"]}}`))
	p.Replace(p2)

	if allowed, _ := p.IsAllowed([]string{"admin"}, "x", "y"); allowed {
		t.Error("expected old roles to be replaced")
	}
	if allowed, _ := p.IsAllowed([]string{"viewer"}, "view", "media"); !allowed {
		t.Error("expected new roles to apply")
	}
}

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		perm     string
		action   string
		resource string
		match    bool
	}{
		{"*", "anything", "anything", true},
		{"media.*", "view", "media", true},
		{"media.*", "delete", "media", true},
		{"media.*", "view", "storage", false},
		{"media.view", "view", "media", true},
		{"media.view", "delete", "media", false},
		{"*.view", "view", "media", true},
		{"*.view", "delete", "media", false},
		{"media.view", "view", "storage", false},
	}
	for _, tt := range tests {
		got := matchPermission(tt.perm, tt.action, tt.resource)
		if got != tt.match {
			t.Errorf("matchPermission(%q, %q, %q) = %v, want %v", tt.perm, tt.action, tt.resource, got, tt.match)
		}
	}
}
