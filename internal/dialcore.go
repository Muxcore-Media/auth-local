package internal

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/Muxcore-Media/core/sdk/go/client"
)

func (m *Module) publishUserDeleted(ctx context.Context, userID string) error {
	var pub EventPublisher
	if c := m.mc.Load(); c != nil {
		pub = c.Events
	}
	return PublishUserDeleted(ctx, pub, m.id, userID)
}

func (m *Module) dialCore(ctx context.Context) {
	meshAddr := os.Getenv("MUXCORE_GRPC_ADDR")
	if meshAddr == "" {
		meshAddr = "localhost:9090"
	}
	var opts []client.Option
	if os.Getenv("MUXCORE_INSECURE_DISABLE_TLS") == "true" || os.Getenv("MUXCORE_GRPC_INSECURE") == "true" {
		opts = append(opts, client.WithInsecure())
	}
	backoff := 100 * time.Millisecond
	for {
		c, err := client.Dial(meshAddr, opts...)
		if err == nil {
			if ctx.Err() != nil {
				c.Close()
				return
			}
			m.mc.Store(c)
			slog.Info("auth-local connected to core", "addr", meshAddr)
			return
		}
		slog.Error("auth-local dial core", "error", err, "retry_in", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff *= 2; backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
}
