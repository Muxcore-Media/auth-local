// Package manifest embeds the module's muxcore.json so the reported version
// has a single source (ADR-0021).
package manifest

import _ "embed"

// ManifestJSON is the raw muxcore.json. Its "version" field is the only source
// of the module's version; see ADR-0021 (module-version-single-source).
//
//go:embed muxcore.json
var ManifestJSON []byte
