package main

import (
	"log/slog"
	"os"

	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"

	"github.com/Muxcore-Media/auth-local/internal"
)

func main() {
	mod := internal.NewModule(internal.Config{})
	if err := modulesdk.Run(modulesdk.Config{
		Module: mod,
	}); err != nil {
		slog.Error("module exited", "error", err)
		os.Exit(1)
	}
}
