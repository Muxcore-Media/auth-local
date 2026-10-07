package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/store"
	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func validationRPCFixture(t *testing.T) (*AuthServer, authv1.AuthServiceClient, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "validation.db")
	s, err := store.NewWithKey(path, []byte(strings.Repeat("v", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, username, password, roles, tenant_id)
		VALUES ('owner', 'owner-name', 'unused', '["admin","user"]', 'household-1')`); err != nil {
		t.Fatal(err)
	}
	srv := New(s, policy.Builtin(), "localhost", nil, "test")
	return srv, sessionManagementClient(t, srv), db
}

func validationBearer(t *testing.T, srv *AuthServer, userID, kind string, ttl time.Duration) string {
	t.Helper()
	session, err := srv.store.CreateSession(userID, kind, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return session.Token
}

func TestValidateRPCDefinitiveInvalid(t *testing.T) {
	srv, client, db := validationRPCFixture(t)
	active := validationBearer(t, srv, "owner", "full", time.Hour)
	revoked := validationBearer(t, srv, "owner", "full", time.Hour)
	if err := srv.store.DeleteSession(revoked); err != nil {
		t.Fatal(err)
	}
	// Delete the user directly to model an orphaned session without cascading
	// session cleanup obscuring the joined lookup's missing-user behavior.
	if _, err := db.Exec(`INSERT INTO users (id, username, password, roles) VALUES ('removed', 'removed', 'unused', '[]')`); err != nil {
		t.Fatal(err)
	}
	orphan := validationBearer(t, srv, "removed", "full", time.Hour)
	if _, err := db.Exec(`DELETE FROM users WHERE id = 'removed'`); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"empty": "", "unknown": "unknown", "revoked": revoked, "removed-user": orphan,
		"expired": validationBearer(t, srv, "owner", "full", -time.Hour),
		"partial": validationBearer(t, srv, "owner", "partial", time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			response, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: token})
			if err != nil || response.GetValid() || response.GetUserId() != "" || len(response.GetRoles()) != 0 || response.GetTenantId() != "" {
				t.Fatalf("invalid bearer = %v, %v", response, err)
			}
		})
	}
	response, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: active})
	if err != nil || !response.GetValid() || response.GetUserId() != "owner" {
		t.Fatalf("unrelated session affected: %v, %v", response, err)
	}
	// A nil direct request is equivalent to a missing token, not a panic.
	if response, err := srv.Validate(context.Background(), nil); err != nil || response.GetValid() {
		t.Fatalf("nil request = %v, %v", response, err)
	}
}

func TestValidateRPCReturnsCurrentClaimsWithoutSecretDecryption(t *testing.T) {
	srv, client, db := validationRPCFixture(t)
	full := validationBearer(t, srv, "owner", "full", time.Hour)
	api := validationBearer(t, srv, "owner", "api-token", time.Hour)
	for _, token := range []string{full, api} {
		response, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: token})
		if err != nil || !response.GetValid() || response.UserId != "owner" || response.Username != "owner-name" || response.TenantId != "household-1" || !reflect.DeepEqual(response.Roles, []string{"admin", "user"}) {
			t.Fatalf("initial claims = %v, %v", response, err)
		}
	}
	if _, err := db.Exec(`UPDATE users SET username = 'new-name', roles = '[]', tenant_id = '',
		totp_secret = 'v1:corrupt-unrelated-secret', totp_enabled = 1 WHERE id = 'owner'`); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{full, api} {
		response, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: token})
		if err != nil || !response.GetValid() || response.UserId != "owner" || response.Username != "new-name" || response.TenantId != "" || len(response.Roles) != 0 {
			t.Fatalf("current claims = %v, %v", response, err)
		}
	}
}

func TestValidateRPCOperationalErrorsPreserveSessions(t *testing.T) {
	for _, tc := range []struct{ name, mutate string }{
		{"roles", `UPDATE users SET roles = 'private-corrupt-value' WHERE id = 'owner'`},
		{"expiry", `UPDATE sessions SET expires_at = 'private-corrupt-value'`},
		{"query", `ALTER TABLE users RENAME TO unavailable_users`},
		{"closed-database", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, client, db := validationRPCFixture(t)
			token := validationBearer(t, srv, "owner", "full", time.Hour)
			before, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: token})
			if err != nil || !before.GetValid() {
				t.Fatalf("baseline validation failed: %v, %v", before, err)
			}
			if tc.mutate != "" {
				if _, err := db.Exec(tc.mutate); err != nil {
					t.Fatal(err)
				}
			} else if err := srv.store.Close(); err != nil {
				t.Fatal(err)
			}
			response, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: token})
			if response != nil || status.Code(err) != codes.Internal || status.Convert(err).Message() != "session validation failed" {
				t.Fatalf("operational failure = %v, %v", response, err)
			}
			// The same joined lookup enforces management RPC authentication.
			adminCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authTokenMetadataKey, token))
			if _, err := client.ListSessions(adminCtx, &authv1.ListSessionsRequest{}); status.Code(err) != codes.Internal {
				t.Fatalf("management lookup hid outage: %v", err)
			}
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("operational failure removed session: %d, %v", count, err)
			}
		})
	}
}

func TestValidateRPCContextFailuresPreserveSessions(t *testing.T) {
	srv, client, db := validationRPCFixture(t)
	token := validationBearer(t, srv, "owner", "full", time.Hour)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	for _, tc := range []struct {
		ctx  context.Context
		want codes.Code
	}{{canceled, codes.Canceled}, {deadline, codes.DeadlineExceeded}} {
		if _, err := client.Validate(tc.ctx, &authv1.ValidateRequest{Token: token}); status.Code(err) != tc.want {
			t.Fatalf("RPC context status = %v, want %v", err, tc.want)
		}
		// An already-canceled transport can fail on the client; directly call
		// the handler too to verify provider-side context error translation.
		if _, err := srv.Validate(tc.ctx, &authv1.ValidateRequest{Token: token}); status.Code(err) != tc.want {
			t.Fatalf("handler context status = %v, want %v", err, tc.want)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cancellation removed session: %d, %v", count, err)
	}
	if response, err := client.Validate(context.Background(), &authv1.ValidateRequest{Token: token}); err != nil || !response.GetValid() {
		t.Fatalf("session no longer validates: %v, %v", response, err)
	}
}
