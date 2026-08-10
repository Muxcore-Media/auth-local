package internal

import (
	"fmt"
	"strings"

	"github.com/Muxcore-Media/core/pkg/contracts"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "policy_file",
			Label:       "RBAC Policy File",
			Type:        contracts.SettingTypeString,
			Value:       m.policyFile,
			Default:     "policies.yaml",
			Description: "Path to RBAC YAML (AUTH_POLICY_FILE); updates reload immediately",
			Group:       "Authorization",
		},
		{
			Key:         "rp_id",
			Label:       "WebAuthn RP ID",
			Type:        contracts.SettingTypeString,
			Value:       m.rpID,
			Default:     "localhost",
			Description: "Relying Party ID / domain (AUTH_RP_ID)",
			Group:       "WebAuthn",
		},
		{
			Key:         "rp_origins",
			Label:       "WebAuthn RP Origins",
			Type:        contracts.SettingTypeString,
			Value:       strings.Join(m.rpOrigins, ","),
			Description: "Comma-separated allowed origins (AUTH_RP_ORIGINS)",
			Group:       "WebAuthn",
		},
		{
			Key:         "rp_name",
			Label:       "WebAuthn RP Name",
			Type:        contracts.SettingTypeString,
			Value:       m.rpName,
			Default:     "MuxCore",
			Description: "Relying Party display name (AUTH_RP_NAME)",
			Group:       "WebAuthn",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "policy_file", "AUTH_POLICY_FILE":
		if value == "" {
			return fmt.Errorf("policy_file must not be empty")
		}
		m.cfgMu.Lock()
		m.policyFile = value
		m.cfgMu.Unlock()
		if m.authSrv == nil {
			return nil
		}
		return m.ReloadPolicy()
	case "rp_id", "AUTH_RP_ID":
		if value == "" {
			return fmt.Errorf("rp_id must not be empty")
		}
		return m.setRelyingParty(value, nil, "")
	case "rp_origins", "AUTH_RP_ORIGINS":
		origins := splitCSV(value)
		if len(origins) == 0 {
			return fmt.Errorf("rp_origins must list at least one origin")
		}
		return m.setRelyingParty("", origins, "")
	case "rp_name", "AUTH_RP_NAME":
		if value == "" {
			return fmt.Errorf("rp_name must not be empty")
		}
		return m.setRelyingParty("", nil, value)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

// setRelyingParty updates RP fields. Empty rpID / nil origins / empty rpName keep current.
func (m *Module) setRelyingParty(rpID string, origins []string, rpName string) error {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()

	newID := m.rpID
	newOrigins := append([]string(nil), m.rpOrigins...)
	newName := m.rpName
	if rpID != "" {
		newID = rpID
	}
	if origins != nil {
		newOrigins = origins
	}
	if rpName != "" {
		newName = rpName
	}

	if m.waHandler != nil {
		if err := m.waHandler.Reconfigure(newID, newOrigins, newName); err != nil {
			return fmt.Errorf("webauthn reconfigure: %w", err)
		}
	}
	if m.authSrv != nil {
		m.authSrv.SetRelyingParty(newID, newOrigins, newName)
	}
	m.rpID = newID
	m.rpOrigins = newOrigins
	m.rpName = newName
	return nil
}
