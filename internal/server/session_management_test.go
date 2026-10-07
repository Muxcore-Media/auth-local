package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Muxcore-Media/auth-local/internal/policy"
	"github.com/Muxcore-Media/auth-local/internal/store"
	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func TestAdministrativeSessionsRequireCurrentEndUserAdmin(t *testing.T) {
	srv := newTestServer(t)
	adminCtx := adminContext(t, srv)
	admin, err := srv.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	user, err := srv.store.CreateUser("user", "password")
	if err != nil {
		t.Fatal(err)
	}
	userCtx := authContext(t, srv, user.ID)
	makeToken := func(userID, kind string, ttl time.Duration) string {
		t.Helper()
		session, err := srv.store.CreateSession(userID, kind, ttl)
		if err != nil {
			t.Fatal(err)
		}
		return session.Token
	}
	withToken := func(ctx context.Context, token string) context.Context {
		return metadata.NewIncomingContext(ctx, metadata.Pairs(authTokenMetadataKey, token))
	}
	partialToken := makeToken(admin.ID, "partial", time.Hour)
	expiredToken := makeToken(admin.ID, "full", -time.Hour)
	apiToken := makeToken(admin.ID, "api-token", time.Hour)
	unknownKindToken := makeToken(admin.ID, "pending", time.Hour)
	cases := []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"missing", context.Background(), codes.Unauthenticated},
		{"invalid", withToken(context.Background(), "invalid"), codes.Unauthenticated},
		{"partial", withToken(context.Background(), partialToken), codes.Unauthenticated},
		{"expired", withToken(context.Background(), expiredToken), codes.Unauthenticated},
		{"unknown-kind", withToken(context.Background(), unknownKindToken), codes.Unauthenticated},
		{"metadata-only", meshContext("muxcore"), codes.Unauthenticated},
		{"verified-mesh-only", verifiedMeshContext("muxcore"), codes.Unauthenticated},
		{"mesh-invalid", withToken(verifiedMeshContext("muxcore"), "invalid"), codes.Unauthenticated},
		{"mesh-partial", withToken(verifiedMeshContext("muxcore"), partialToken), codes.Unauthenticated},
		{"mesh-expired", withToken(verifiedMeshContext("muxcore"), expiredToken), codes.Unauthenticated},
		{"non-admin", userCtx, codes.PermissionDenied},
		{"mesh-non-admin", withToken(verifiedMeshContext("muxcore"), sessionTokenFromContext(userCtx)), codes.PermissionDenied},
		{"admin-full", adminCtx, codes.OK},
		{"admin-api", withToken(context.Background(), apiToken), codes.OK},
		{"mesh-admin", withToken(verifiedMeshContext("muxcore"), sessionTokenFromContext(adminCtx)), codes.OK},
	}
	for name, call := range map[string]func(context.Context) error{
		"list": func(ctx context.Context) error {
			_, err := srv.ListSessions(ctx, &authv1.ListSessionsRequest{})
			return err
		},
		"revoke": func(ctx context.Context) error {
			_, err := srv.RevokeSession(ctx, &authv1.RevokeSessionRequest{UserId: user.ID, SessionId: "unknown"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if err := call(tc.ctx); status.Code(err) != tc.code {
						t.Fatalf("status = %v, want %v: %v", status.Code(err), tc.code, err)
					}
				})
			}
			if err := srv.store.SetRoles(admin.ID, []string{"viewer"}); err != nil {
				t.Fatal(err)
			}
			for _, ctx := range []context.Context{adminCtx, withToken(context.Background(), apiToken)} {
				if err := call(ctx); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("demotion not enforced: %v", err)
				}
			}
			if err := srv.store.SetRoles(admin.ID, []string{"admin"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdministrativeSessionsInvalidInputAndCredentialIsolation(t *testing.T) {
	srv := newTestServer(t)
	ctx := adminContext(t, srv)
	admin, err := srv.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.CreateFullSession(admin.ID); err != nil {
		t.Fatal(err)
	}
	page, err := srv.ListSessions(ctx, &authv1.ListSessionsRequest{PageSize: 1})
	if err != nil || len(page.GetSessions()) != 1 || page.GetNextPageToken() == "" {
		t.Fatalf("first page: %v, %v", page, err)
	}
	for _, req := range []*authv1.ListSessionsRequest{
		{PageSize: -1}, {PageSize: 501}, {PageToken: "malformed"}, {PageToken: strings.Repeat("a", 4097)},
		{UserId: admin.ID, PageToken: page.NextPageToken},
	} {
		if _, err := srv.ListSessions(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid list request accepted: %v", err)
		}
	}
	for _, req := range []*authv1.RevokeSessionRequest{
		nil, {}, {UserId: admin.ID}, {SessionId: page.Sessions[0].SessionId},
	} {
		if _, err := srv.RevokeSession(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid revoke request accepted: %v", err)
		}
	}
	for _, credential := range []string{page.Sessions[0].SessionId, page.NextPageToken} {
		validation, err := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: credential})
		if err != nil || validation.GetValid() {
			t.Fatalf("management value validated: %v, %v", validation, err)
		}
		identity, err := srv.ExtractIdentity(context.Background(), &authv1.ExtractIdentityRequest{Token: credential})
		if err != nil || identity.GetFound() {
			t.Fatalf("management value identified: %v, %v", identity, err)
		}
		data, err := json.Marshal(map[string]string{"key": credential})
		if err != nil {
			t.Fatal(err)
		}
		auth, err := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{CredentialType: "api-key", CredentialData: data})
		if err != nil || auth.GetAuthenticated() {
			t.Fatalf("management value authenticated: %v, %v", auth, err)
		}
		invalidCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authTokenMetadataKey, credential))
		if _, err := srv.ListSessions(invalidCtx, &authv1.ListSessionsRequest{}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("management value authorized: %v", err)
		}
		if _, err := srv.RevokeSession(invalidCtx, &authv1.RevokeSessionRequest{UserId: admin.ID, SessionId: "missing"}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("management value authorized revoke: %v", err)
		}
	}
	for _, value := range []string{page.Sessions[0].CreatedAt, page.Sessions[0].ExpiresAt} {
		if stamp, err := time.Parse(time.RFC3339, value); err != nil || stamp.Location() != time.UTC {
			t.Fatalf("timestamp is not UTC RFC3339: %q, %v", value, err)
		}
	}
}

func sessionManagementClient(t *testing.T, srv *AuthServer) authv1.AuthServiceClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	srv.RegisterWithGRPC(server)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///sessions", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})
	return authv1.NewAuthServiceClient(conn)
}

func TestAdministrativeSessionRevocationOverGRPC(t *testing.T) {
	srv := newTestServer(t)
	adminCtx := adminContext(t, srv)
	client := sessionManagementClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(authTokenMetadataKey, sessionTokenFromContext(adminCtx)))
	user, err := srv.store.CreateUser("target", "password")
	if err != nil {
		t.Fatal(err)
	}
	full, err := srv.store.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := srv.store.CreateFullSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := srv.store.CreateAPIToken(user.ID, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(map[string]string{"key": key})
	if err != nil {
		t.Fatal(err)
	}
	api, err := client.Authenticate(ctx, &authv1.AuthenticateRequest{CredentialType: "api-key", CredentialData: keyJSON})
	if err != nil || !api.GetAuthenticated() {
		t.Fatalf("API authentication: %v, %v", api, err)
	}
	list, err := client.ListSessions(ctx, &authv1.ListSessionsRequest{UserId: user.ID})
	if err != nil || len(list.GetSessions()) != 3 {
		t.Fatalf("list over transport: %v, %v", list, err)
	}
	serialized, err := protojson.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	for _, bearer := range []string{full.Token, sibling.Token, api.SessionToken, key} {
		if strings.Contains(string(serialized), bearer) {
			t.Fatal("response leaked credential")
		}
	}
	// Identify the single API session by kind; the management view contains no
	// bearer material to use as a lookup key.
	entries, _, err := srv.store.ListActiveSessions(context.Background(), user.ID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	var apiID string
	for _, entry := range entries {
		if entry.Kind == "api-token" {
			apiID = entry.ID
		}
	}
	if apiID == "" {
		t.Fatal("minted API session missing")
	}
	if _, err := client.RevokeSession(ctx, &authv1.RevokeSessionRequest{UserId: "other-owner", SessionId: apiID}); err != nil {
		t.Fatal(err)
	}
	stillValid, err := client.Validate(ctx, &authv1.ValidateRequest{Token: api.SessionToken})
	if err != nil || !stillValid.GetValid() {
		t.Fatalf("wrong-owner revoke affected bearer: %v, %v", stillValid, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := client.RevokeSession(ctx, &authv1.RevokeSessionRequest{UserId: user.ID, SessionId: apiID}); err != nil {
			t.Fatal(err)
		}
	}
	validation, err := client.Validate(ctx, &authv1.ValidateRequest{Token: api.SessionToken})
	if err != nil || validation.GetValid() {
		t.Fatalf("revoked bearer validated: %v, %v", validation, err)
	}
	identity, err := client.ExtractIdentity(ctx, &authv1.ExtractIdentityRequest{Token: api.SessionToken})
	if err != nil || identity.GetFound() {
		t.Fatalf("revoked bearer identified: %v, %v", identity, err)
	}
	for _, bearer := range []string{full.Token, sibling.Token} {
		valid, err := client.Validate(ctx, &authv1.ValidateRequest{Token: bearer})
		if err != nil || !valid.GetValid() {
			t.Fatalf("sibling invalid: %v, %v", valid, err)
		}
	}
	apiAgain, err := client.Authenticate(ctx, &authv1.AuthenticateRequest{CredentialType: "api-key", CredentialData: keyJSON})
	if err != nil || !apiAgain.GetAuthenticated() || apiAgain.SessionToken == api.SessionToken {
		t.Fatalf("originating API key affected: %v, %v", apiAgain, err)
	}
	// Revoking the administrator's own session applies to the next RPC too.
	admin, err := srv.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	adminList, err := client.ListSessions(ctx, &authv1.ListSessionsRequest{UserId: admin.ID})
	if err != nil || len(adminList.GetSessions()) != 1 {
		t.Fatalf("admin list: %v, %v", adminList, err)
	}
	if _, err := client.RevokeSession(ctx, &authv1.RevokeSessionRequest{UserId: admin.ID, SessionId: adminList.Sessions[0].SessionId}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListSessions(ctx, &authv1.ListSessionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked administrator authorized: %v", err)
	}
}

func TestAdministrativeSessionsDatabaseErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.db")
	s, err := store.NewWithKey(path, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	srv := New(s, policy.Builtin(), "localhost", nil, "test")
	ctx := adminContext(t, srv)
	page, err := srv.ListSessions(ctx, &authv1.ListSessionsRequest{})
	if err != nil || len(page.GetSessions()) != 1 {
		t.Fatalf("list: %v, %v", page, err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER fail_revoke BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END`); err != nil {
		t.Fatal(err)
	}
	entry := page.Sessions[0]
	if _, err := srv.RevokeSession(ctx, &authv1.RevokeSessionRequest{UserId: entry.UserId, SessionId: entry.SessionId}); status.Code(err) != codes.Internal {
		t.Fatalf("write failure reported success: %v", err)
	}
	valid, err := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: sessionTokenFromContext(ctx)})
	if err != nil || !valid.GetValid() {
		t.Fatalf("failed delete changed bearer: %v, %v", valid, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := srv.ListSessions(canceled, &authv1.ListSessionsRequest{}); status.Code(err) != codes.Canceled {
		t.Fatalf("list cancellation: %v", err)
	}
	if _, err := srv.RevokeSession(canceled, &authv1.RevokeSessionRequest{UserId: entry.UserId, SessionId: entry.SessionId}); status.Code(err) != codes.Canceled {
		t.Fatalf("revoke cancellation: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.ListSessions(ctx, &authv1.ListSessionsRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("database failure mapped incorrectly: %v", err)
	}
	if _, err := srv.RevokeSession(ctx, &authv1.RevokeSessionRequest{UserId: entry.UserId, SessionId: entry.SessionId}); status.Code(err) != codes.Internal {
		t.Fatalf("database failure mapped incorrectly: %v", err)
	}
}
