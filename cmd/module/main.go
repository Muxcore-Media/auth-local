package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Muxcore-Media/auth-local/internal/server"
	"github.com/Muxcore-Media/auth-local/internal/store"
	modulev1 "github.com/Muxcore-Media/core/proto/gen/muxcore/module/v1"
)

func main() {
	meshAddr := flag.String("muxcore-mesh-addr", "localhost:9090", "gRPC address of the MuxCore mesh")
	moduleID := flag.String("muxcore-module-id", "auth-local", "Module identifier")
	grpcAddr := flag.String("grpc-addr", ":9400", "Address for this module's gRPC AuthService")
	dbPath := flag.String("db-path", "", "Path to SQLite database (default: ~/.muxcore/auth.db)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("starting auth-local", "version", "0.1.0")

	if *dbPath == "" {
		home, _ := os.UserHomeDir()
		*dbPath = filepath.Join(home, ".muxcore", "auth.db")
	}
	os.MkdirAll(filepath.Dir(*dbPath), 0700)

	st, err := store.New(*dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	// Start gRPC server.
	lis, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		slog.Error("failed to listen", "addr", *grpcAddr, "error", err)
		os.Exit(1)
	}

	grpcSrv := grpc.NewServer()
	authSrv := server.New(st)
	authSrv.RegisterWithGRPC(grpcSrv)

	go func() {
		slog.Info("gRPC AuthService listening", "addr", *grpcAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			slog.Error("gRPC server error", "error", err)
		}
	}()

	// Connect to core's mesh.
	conn, err := grpc.NewClient(*meshAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		slog.Error("failed to connect to core mesh", "addr", *meshAddr, "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Register as a sidecar module with all three auth capabilities.
	regClient := modulev1.NewModuleRegistrationClient(conn)
	resp, err := regClient.Register(context.Background(), &modulev1.RegisterRequest{
		ModuleId: *moduleID,
		ModuleInfo: &modulev1.ModuleInfo{
			Id:           *moduleID,
			Name:         "Auth Local",
			Version:      "0.1.0",
			Description:  "Local authentication, authorization, and identity provider",
			Author:       "MuxCore",
			Roles:        []string{"security", "auth"},
			Capabilities: []string{"auth", "authorizer", "identity"},
			HttpAddr:     *grpcAddr,
		},
	})
	if err != nil {
		slog.Error("registration failed", "error", err)
		os.Exit(1)
	}
	if !resp.Accepted {
		slog.Error("registration rejected", "reason", resp.Error)
		os.Exit(1)
	}
	slog.Info("module registered with core",
		"id", *moduleID,
		"mesh_addr", resp.MeshAddr,
		"node_id", resp.NodeId,
	)

	// Background session cleanup.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := st.CleanupExpiredSessions(); err != nil {
				slog.Warn("session cleanup failed", "error", err)
			}
		}
	}()

	// Wait for shutdown signal.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()

	slog.Info("shutting down...")
	regClient.Unregister(context.Background(), &modulev1.UnregisterRequest{ModuleId: *moduleID})
	grpcSrv.GracefulStop()
	slog.Info("shutdown complete")
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: auth-local [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}
