package store

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestMain lowers the bcrypt cost for this test binary only: user creation
// at the production cost (12) takes seconds under the race detector.
func TestMain(m *testing.M) {
	SetPasswordHashCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
