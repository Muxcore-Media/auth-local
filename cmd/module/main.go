package main

import (
	"flag"
	"log/slog"
	"os"

	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"

	"github.com/Muxcore-Media/auth-local/internal"
)

func main() {
	dbPath := flag.String("db-path", "", "SQLite database path (AUTH_DB_PATH)")
	policyFile := flag.String("policy-file", "", "RBAC policy YAML path (AUTH_POLICY_FILE)")
	grpcAddr := flag.String("grpc-addr", "", "gRPC listen address (AUTH_GRPC_ADDR)")
	httpAddr := flag.String("http-addr", "", "HTTP listen address (AUTH_HTTP_ADDR)")
	rpID := flag.String("rp-id", "", "WebAuthn relying party ID (AUTH_RP_ID)")
	rpOrigins := flag.String("rp-origins", "", "Comma-separated WebAuthn origins (AUTH_RP_ORIGINS)")
	rpName := flag.String("rp-name", "", "WebAuthn relying party display name (AUTH_RP_NAME)")
	flag.Parse()

	mod := internal.NewModule(internal.Config{
		DBPath:     *dbPath,
		PolicyFile: *policyFile,
		GRPCAddr:   *grpcAddr,
		HTTPAddr:   *httpAddr,
		RPID:       *rpID,
		RPOrigins:  *rpOrigins,
		RPName:     *rpName,
	})
	insecure := os.Getenv("MUXCORE_INSECURE_DISABLE_TLS") == "true" || os.Getenv("MUXCORE_GRPC_INSECURE") == "true"
	if err := modulesdk.Run(modulesdk.Config{
		Module:   mod,
		Insecure: insecure,
	}); err != nil {
		slog.Error("module exited", "error", err)
		os.Exit(1)
	}
}
