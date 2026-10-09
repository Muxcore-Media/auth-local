package webauthn

import (
	"os"
	"testing"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// TestMain lowers the bcrypt cost for this test binary only: user creation
// at the production cost (12) takes seconds under the race detector.
func TestMain(m *testing.M) {
	authStore.SetPasswordHashCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
