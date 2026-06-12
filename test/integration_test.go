//go:build integration

package test

import (
	"context"
	"os"
	"testing"
	"time"

	modulev1 "github.com/Muxcore-Media/core/proto/gen/muxcore/module/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestModuleRegistration(t *testing.T) {
	addr := os.Getenv("MUXCORE_GRPC_ADDR")
	if addr == "" {
		t.Skip("MUXCORE_GRPC_ADDR not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial core: %v", err)
	}
	defer conn.Close()

	reg := modulev1.NewModuleRegistrationClient(conn)
	resp, err := reg.Register(ctx, &modulev1.RegisterRequest{
		ModuleId: "test-module",
		ModuleInfo: &modulev1.ModuleInfo{
			Id:           "test-module",
			Name:         "Test Module",
			Version:      "0.0.0-test",
			Roles:        []string{"test"},
			Capabilities: []string{"test"},
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("registration rejected: %s", resp.Error)
	}
	t.Logf("registered, mesh_addr=%s node_id=%s", resp.MeshAddr, resp.NodeId)

	_, err = reg.Unregister(ctx, &modulev1.UnregisterRequest{ModuleId: "test-module"})
	if err != nil {
		t.Fatalf("unregister: %v", err)
	}
}
