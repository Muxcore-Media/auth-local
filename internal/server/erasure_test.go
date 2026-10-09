package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

func withBearer(ctx context.Context, token string) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(authTokenMetadataKey, token)
	return metadata.NewIncomingContext(ctx, md)
}

func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("code = %v (%v); want %v", got, err, want)
	}
}

func mkUser(t *testing.T, srv *AuthServer, name, tenant string, roles ...string) *authStore.User {
	t.Helper()
	u, err := srv.store.CreateUserTenant(name, "password123", tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) > 0 {
		if err := srv.store.SetRoles(u.ID, roles); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

func bearer(t *testing.T, srv *AuthServer, userID, kind string, ttl time.Duration) string {
	t.Helper()
	sess, err := srv.store.CreateSession(userID, kind, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return sess.Token
}

func bearerCtx(t *testing.T, srv *AuthServer, userID string) context.Context {
	t.Helper()
	return withBearer(context.Background(), bearer(t, srv, userID, "full", time.Hour))
}

// TestDeleteUserRequiresCurrentAdminBearer is the ADR-0035 DeleteUser
// negative matrix: no mesh-peer bypass, partial/expired/non-admin bearers
// refused, and the target untouched by every refused call.
func TestDeleteUserRequiresCurrentAdminBearer(t *testing.T) {
	srv := newTestServer(t)
	admin := mkUser(t, srv, "admin", "", "admin")
	member := mkUser(t, srv, "member", "")
	target := mkUser(t, srv, "target", "")

	cases := []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"no credentials", context.Background(), codes.Unauthenticated},
		{"spoofed x-caller-id", meshContext("admin-ui"), codes.Unauthenticated},
		{"module certificate without bearer", verifiedMeshContext("admin-ui"), codes.Unauthenticated},
		{"invalid bearer", withBearer(context.Background(), "nope"), codes.Unauthenticated},
		{"partial bearer", withBearer(context.Background(), bearer(t, srv, admin.ID, "partial", time.Hour)), codes.Unauthenticated},
		{"expired bearer", withBearer(context.Background(), bearer(t, srv, admin.ID, "full", -time.Hour)), codes.Unauthenticated},
		{"module certificate with partial admin bearer", withBearer(verifiedMeshContext("admin-ui"), bearer(t, srv, admin.ID, "partial", time.Hour)), codes.Unauthenticated},
		{"non-admin bearer", bearerCtx(t, srv, member.ID), codes.PermissionDenied},
		{"module certificate with non-admin bearer", withBearer(verifiedMeshContext("admin-ui"), bearer(t, srv, member.ID, "full", time.Hour)), codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := srv.DeleteUser(tc.ctx, &authv1.DeleteUserRequest{UserId: target.ID})
			requireCode(t, err, tc.code)
			if resp.GetErasureId() != "" {
				t.Fatal("erasure id returned on failure")
			}
			if _, err := srv.store.GetUser(target.ID); err != nil {
				t.Fatalf("target deleted by a refused call: %v", err)
			}
		})
	}

	// A role revoked since login is rechecked on every call (ADR-0026 §2).
	demoted := mkUser(t, srv, "demoted", "", "admin")
	demotedCtx := bearerCtx(t, srv, demoted.ID)
	if err := srv.store.SetRoles(demoted.ID, []string{"user"}); err != nil {
		t.Fatal(err)
	}
	_, err := srv.DeleteUser(demotedCtx, &authv1.DeleteUserRequest{UserId: target.ID})
	requireCode(t, err, codes.PermissionDenied)

	// An admin API-token session is a fully authenticated bearer.
	apiCtx := withBearer(context.Background(), bearer(t, srv, admin.ID, "api-token", time.Hour))
	resp, err := srv.DeleteUser(apiCtx, &authv1.DeleteUserRequest{UserId: target.ID})
	if err != nil || resp.GetErasureId() == "" {
		t.Fatalf("admin api-token DeleteUser = %v, %v", resp, err)
	}
}

func TestDeleteUserTenantSelfAndIdempotency(t *testing.T) {
	srv := newTestServer(t)
	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	foreignAdmin := mkUser(t, srv, "foreign-admin", "household-2", "admin")
	foreign := mkUser(t, srv, "foreign", "household-2")
	victim := mkUser(t, srv, "victim", "")
	ctx := bearerCtx(t, srv, admin.ID)

	_, err := srv.DeleteUser(ctx, &authv1.DeleteUserRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: admin.ID})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: foreign.ID})
	requireCode(t, err, codes.NotFound)
	if _, err := srv.store.GetUser(foreign.ID); err != nil {
		t.Fatal("cross-tenant target deleted")
	}
	_, err = srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: "never-seen"})
	requireCode(t, err, codes.NotFound)

	// Victim with every kind of bearer and credential.
	fullTok := bearer(t, srv, victim.ID, "full", time.Hour)
	partialTok := bearer(t, srv, victim.ID, "partial", time.Hour)
	apiKey, _, err := srv.store.CreateAPIToken(victim.ID, "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	apiSess, err := srv.store.ValidateAPIToken(apiKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SetTOTPSecret(victim.ID, "KRSXG5CTMVRXEZLU"); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddWebAuthnCredential(victim.ID, []byte("pk")); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SaveWebAuthnSession(victim.ID, "victim-challenge", []byte{1}); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{fullTok, apiSess.Token} {
		if v, _ := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: tok}); !v.GetValid() {
			t.Fatal("precondition: victim bearer should validate")
		}
	}

	resp, err := srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: victim.ID})
	if err != nil {
		t.Fatal(err)
	}
	erasureID := resp.GetErasureId()
	if !authStore.ValidErasureID(erasureID) || strings.Contains(erasureID, victim.ID) {
		t.Fatalf("erasure_id %q", erasureID)
	}
	for name, tok := range map[string]string{"full": fullTok, "api-token": apiSess.Token, "partial": partialTok} {
		v, err := srv.Validate(context.Background(), &authv1.ValidateRequest{Token: tok})
		if err != nil || v.GetValid() {
			t.Errorf("%s session still validates after DeleteUser: %v, %v", name, v, err)
		}
	}
	if a, _ := srv.Authenticate(context.Background(), &authv1.AuthenticateRequest{
		CredentialType: "api-key", CredentialData: []byte(`{"key":"` + apiKey + `"}`),
	}); a.GetAuthenticated() {
		t.Error("API key still authenticates")
	}
	if _, enabled, _ := srv.store.GetTOTPSecret(victim.ID); enabled {
		t.Error("TOTP row survived")
	}
	if n, _ := srv.store.WebAuthnCredentialCount(victim.ID); n != 0 {
		t.Errorf("%d passkeys survived", n)
	}
	if _, err := srv.store.GetWebAuthnSession("victim-challenge"); err == nil {
		t.Error("passkey session survived")
	}

	again, err := srv.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: victim.ID})
	if err != nil || again.GetErasureId() != erasureID {
		t.Fatalf("repeat DeleteUser = %v, %v; want the same erasure id %q", again, err, erasureID)
	}
	// Another tenant's admin cannot see the tombstone.
	_, err = srv.DeleteUser(bearerCtx(t, srv, foreignAdmin.ID), &authv1.DeleteUserRequest{UserId: victim.ID})
	requireCode(t, err, codes.NotFound)
	// A user created over gRPC never gets a tombstoned id.
	created, err := srv.CreateUser(ctx, &authv1.CreateUserRequest{Username: "victim", Password: "password123"})
	if err != nil || created.GetError() != "" || created.GetUserId() == victim.ID {
		t.Fatalf("username reuse = %v, %v", created, err)
	}
}

// TestDeleteUserConcurrentLastTwoAdmins: the only two admins delete each other
// concurrently over gRPC; exactly one succeeds and one admin remains. (Through
// the RPC a lone admin can never target the last admin: the caller is itself
// a current admin of the tenant. The deterministic proof that the count is
// taken inside the write transaction is the store-level test of the same
// name; this checks the RPC path end to end.)
func TestDeleteUserConcurrentLastTwoAdmins(t *testing.T) {
	for round := 0; round < 3; round++ {
		srv := newTestServer(t)
		a := mkUser(t, srv, "admin-a", "", "admin")
		b := mkUser(t, srv, "admin-b", "", "admin")
		ctxA, ctxB := bearerCtx(t, srv, a.ID), bearerCtx(t, srv, b.ID)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, errs[0] = srv.DeleteUser(ctxA, &authv1.DeleteUserRequest{UserId: b.ID})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, errs[1] = srv.DeleteUser(ctxB, &authv1.DeleteUserRequest{UserId: a.ID})
		}()
		close(start)
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch status.Code(err) {
			case codes.OK:
				ok++
			case codes.FailedPrecondition, codes.Unauthenticated:
			default:
				t.Fatalf("round %d: unexpected %v", round, err)
			}
		}
		users, _ := srv.store.ListUsers()
		if ok != 1 || len(users) != 1 {
			t.Fatalf("round %d: %d succeeded (%v), %d users left; want exactly one", round, ok, errs, len(users))
		}
	}
}

func ledgerServer(t *testing.T, consumers, required []string) *AuthServer {
	t.Helper()
	srv := newTestServer(t)
	srv.SetErasureConfig(ErasureConfig{Consumers: consumers, Required: required})
	return srv
}

func eraseVia(t *testing.T, srv *AuthServer, adminCtx context.Context, userID string) string {
	t.Helper()
	resp, err := srv.DeleteUser(adminCtx, &authv1.DeleteUserRequest{UserId: userID})
	if err != nil {
		t.Fatal(err)
	}
	return resp.GetErasureId()
}

// plaintextPeerContext is a plaintext (no TLS) connection carrying x-caller-id.
func plaintextPeerContext(callerID string) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	return metadata.NewIncomingContext(ctx, metadata.Pairs(callerIDMetadataKey, callerID))
}

func TestLedgerRPCAuthMatrix(t *testing.T) {
	srv := ledgerServer(t, []string{"userdata-local", "request-media"}, nil)
	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	adminCtx := bearerCtx(t, srv, admin.ID)
	victim := mkUser(t, srv, "victim", "")
	erasureID := eraseVia(t, srv, adminCtx, victim.ID)
	adminTok := bearer(t, srv, admin.ID, "full", time.Hour)

	spoofed := verifiedMeshContext("userdata-local")
	md, _ := metadata.FromIncomingContext(spoofed)
	md = md.Copy()
	md.Set(callerIDMetadataKey, "request-media")
	spoofed = metadata.NewIncomingContext(spoofed, md)

	cases := []struct {
		name string
		ctx  context.Context
		code codes.Code
	}{
		{"no peer", context.Background(), codes.Unauthenticated},
		{"x-caller-id only (no TLS peer)", meshContext("userdata-local"), codes.Unauthenticated},
		{"plaintext peer, dev trust off", plaintextPeerContext("userdata-local"), codes.Unauthenticated},
		{"unverified certificate", unverifiedMeshContext("userdata-local"), codes.Unauthenticated},
		{"admin user bearer", withBearer(context.Background(), adminTok), codes.Unauthenticated},
		{"allowlisted certificate plus user bearer", withBearer(verifiedMeshContext("userdata-local"), adminTok), codes.PermissionDenied},
		{"wrong CN", verifiedMeshContext("admin-ui"), codes.PermissionDenied},
		{"allowlisted CN", verifiedMeshContext("userdata-local"), codes.OK},
		{"allowlisted CN with spoofed x-caller-id", spoofed, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := srv.ListUserErasures(tc.ctx, &authv1.ListUserErasuresRequest{})
			requireCode(t, err, tc.code)
			if tc.code != codes.OK && len(resp.GetErasures()) != 0 {
				t.Fatal("ledger data returned to a refused caller")
			}
			_, err = srv.AckUserErasure(tc.ctx, &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: authv1.ErasureOutcome_ERASURE_OUTCOME_OK})
			requireCode(t, err, tc.code)
		})
	}

	// The acknowledgement is attributed to the verified CN, never to the
	// spoofed x-caller-id.
	st, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{ErasureId: erasureID})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range st.GetErasures()[0].GetModules() {
		if m.GetModuleId() != "userdata-local" {
			t.Fatalf("acknowledgement recorded for %q", m.GetModuleId())
		}
	}
	list, err := srv.ListUserErasures(verifiedMeshContext("request-media"), &authv1.ListUserErasuresRequest{})
	if err != nil || len(list.GetErasures()) != 1 || list.GetErasures()[0].GetAcknowledgedByCaller() {
		t.Fatalf("request-media sees %v, %v; want unacknowledged", list, err)
	}
	list, err = srv.ListUserErasures(verifiedMeshContext("userdata-local"), &authv1.ListUserErasuresRequest{})
	if err != nil || !list.GetErasures()[0].GetAcknowledgedByCaller() {
		t.Fatalf("userdata-local sees %v, %v; want acknowledged", list, err)
	}
	e := list.GetErasures()[0]
	if e.GetErasureId() != erasureID || e.GetUserId() != victim.ID || e.GetTenantId() != "" {
		t.Fatalf("tombstone = %v", e)
	}
	if _, err := time.Parse(time.RFC3339Nano, e.GetDeletedAt()); err != nil {
		t.Fatalf("deleted_at %q: %v", e.GetDeletedAt(), err)
	}
}

func TestLedgerEmptyAllowlistFailsClosed(t *testing.T) {
	for _, consumers := range [][]string{nil, {}, {" ", ""}} {
		srv := ledgerServer(t, consumers, nil)
		_, err := srv.ListUserErasures(verifiedMeshContext("userdata-local"), &authv1.ListUserErasuresRequest{})
		requireCode(t, err, codes.PermissionDenied)
		_, err = srv.AckUserErasure(verifiedMeshContext("userdata-local"), &authv1.AckUserErasureRequest{ErasureId: "er_x", Outcome: authv1.ErasureOutcome_ERASURE_OUTCOME_OK})
		requireCode(t, err, codes.PermissionDenied)
	}
	// A server never configured at all also fails closed.
	srv := newTestServer(t)
	_, err := srv.ListUserErasures(verifiedMeshContext("userdata-local"), &authv1.ListUserErasuresRequest{})
	requireCode(t, err, codes.PermissionDenied)
}

func TestLedgerDevProfileTrustsCallerIDOnlyWithoutTLS(t *testing.T) {
	srv := newTestServer(t)
	srv.SetErasureConfig(ErasureConfig{Consumers: []string{"userdata-local"}, TrustCallerIDWithoutTLS: true})
	if _, err := srv.ListUserErasures(plaintextPeerContext("userdata-local"), &authv1.ListUserErasuresRequest{}); err != nil {
		t.Fatalf("dev plaintext caller: %v", err)
	}
	_, err := srv.ListUserErasures(plaintextPeerContext("admin-ui"), &authv1.ListUserErasuresRequest{})
	requireCode(t, err, codes.PermissionDenied)
	// A TLS connection never falls back to x-caller-id, even in dev.
	_, err = srv.ListUserErasures(unverifiedMeshContext("userdata-local"), &authv1.ListUserErasuresRequest{})
	requireCode(t, err, codes.Unauthenticated)
}

func TestAckUserErasureValidation(t *testing.T) {
	srv := ledgerServer(t, []string{"userdata-local"}, nil)
	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	victim := mkUser(t, srv, "victim", "")
	erasureID := eraseVia(t, srv, bearerCtx(t, srv, admin.ID), victim.ID)
	ctx := verifiedMeshContext("userdata-local")
	ok := authv1.ErasureOutcome_ERASURE_OUTCOME_OK
	many := map[string]int64{}
	for i := 0; i < 33; i++ {
		many[fmt.Sprintf("k%d", i)] = 1
	}
	cases := []struct {
		name string
		req  *authv1.AckUserErasureRequest
		code codes.Code
	}{
		{"missing id", &authv1.AckUserErasureRequest{Outcome: ok}, codes.InvalidArgument},
		{"malformed id", &authv1.AckUserErasureRequest{ErasureId: "bad id", Outcome: ok}, codes.InvalidArgument},
		{"unknown id", &authv1.AckUserErasureRequest{ErasureId: "er_unknown", Outcome: ok}, codes.NotFound},
		{"unspecified outcome", &authv1.AckUserErasureRequest{ErasureId: erasureID}, codes.InvalidArgument},
		{"out-of-range outcome", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: 42}, codes.InvalidArgument},
		{"uppercase detail", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, DetailCode: "Apply"}, codes.InvalidArgument},
		{"detail with personal data", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, DetailCode: "user@example"}, codes.InvalidArgument},
		{"long detail", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, DetailCode: strings.Repeat("a", 65)}, codes.InvalidArgument},
		{"too many counts", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, Counts: many}, codes.InvalidArgument},
		{"negative count", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, Counts: map[string]int64{"rows": -1}}, codes.InvalidArgument},
		{"bad count key", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, Counts: map[string]int64{"Rows ": 1}}, codes.InvalidArgument},
		{"valid failed", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: authv1.ErasureOutcome_ERASURE_OUTCOME_FAILED, DetailCode: "apply_failed"}, codes.OK},
		{"valid unsupported", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: authv1.ErasureOutcome_ERASURE_OUTCOME_UNSUPPORTED, DetailCode: "owner_unsupported"}, codes.OK},
		{"valid ok", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, Counts: map[string]int64{"user_blobs": 3, "a.b-c_d": 0}}, codes.OK},
		{"idempotent repeat", &authv1.AckUserErasureRequest{ErasureId: erasureID, Outcome: ok, Counts: map[string]int64{"user_blobs": 3}}, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := srv.AckUserErasure(ctx, tc.req)
			requireCode(t, err, tc.code)
		})
	}
	list, err := srv.ListUserErasures(ctx, &authv1.ListUserErasuresRequest{})
	if err != nil || !list.GetErasures()[0].GetAcknowledgedByCaller() {
		t.Fatalf("latest OK ack not reflected: %v, %v", list, err)
	}
}

func TestListUserErasuresPaging(t *testing.T) {
	srv := ledgerServer(t, []string{"userdata-local"}, nil)
	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	adminCtx := bearerCtx(t, srv, admin.ID)
	want := map[string]bool{}
	for i := 0; i < 3; i++ {
		u := mkUser(t, srv, fmt.Sprintf("u%d", i), "")
		want[eraseVia(t, srv, adminCtx, u.ID)] = true
	}
	ctx := verifiedMeshContext("userdata-local")
	seen := map[string]bool{}
	token := ""
	for pages := 0; ; pages++ {
		if pages > 3 {
			t.Fatal("paging did not terminate")
		}
		resp, err := srv.ListUserErasures(ctx, &authv1.ListUserErasuresRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.GetErasures()) > 2 {
			t.Fatalf("page of %d", len(resp.GetErasures()))
		}
		for _, e := range resp.GetErasures() {
			if seen[e.GetErasureId()] {
				t.Fatalf("duplicate %s across pages", e.GetErasureId())
			}
			seen[e.GetErasureId()] = true
		}
		if resp.GetNextPageToken() == "" {
			break
		}
		token = resp.GetNextPageToken()
	}
	if len(seen) != len(want) {
		t.Fatalf("saw %d tombstones, want %d", len(seen), len(want))
	}
	for _, req := range []*authv1.ListUserErasuresRequest{{PageSize: -1}, {PageSize: 501}, {PageToken: "forged"}} {
		_, err := srv.ListUserErasures(ctx, req)
		requireCode(t, err, codes.InvalidArgument)
	}
}

func TestGetUserErasureStatus(t *testing.T) {
	srv := ledgerServer(t, []string{"userdata-local", "request-media", "playback-monitor"}, []string{"userdata-local", "request-media"})
	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	foreignAdmin := mkUser(t, srv, "foreign-admin", "household-2", "admin")
	_ = mkUser(t, srv, "foreign-admin2", "household-2", "admin")
	member := mkUser(t, srv, "member", "")
	adminCtx := bearerCtx(t, srv, admin.ID)
	e1 := eraseVia(t, srv, adminCtx, mkUser(t, srv, "v1", "").ID)
	e2 := eraseVia(t, srv, adminCtx, mkUser(t, srv, "v2", "").ID)
	eForeign := eraseVia(t, srv, bearerCtx(t, srv, foreignAdmin.ID), mkUser(t, srv, "v3", "household-2").ID)

	// Authorization: admin bearer only; no mesh-peer bypass.
	for _, tc := range []struct {
		ctx  context.Context
		code codes.Code
	}{
		{context.Background(), codes.Unauthenticated},
		{verifiedMeshContext("admin-ui"), codes.Unauthenticated},
		{verifiedMeshContext("userdata-local"), codes.Unauthenticated},
		{bearerCtx(t, srv, member.ID), codes.PermissionDenied},
	} {
		_, err := srv.GetUserErasureStatus(tc.ctx, &authv1.GetUserErasureStatusRequest{})
		requireCode(t, err, tc.code)
	}

	ack := func(module, id string, o authv1.ErasureOutcome) {
		t.Helper()
		if _, err := srv.AckUserErasure(verifiedMeshContext(module), &authv1.AckUserErasureRequest{ErasureId: id, Outcome: o}); err != nil {
			t.Fatal(err)
		}
	}
	okO, failO := authv1.ErasureOutcome_ERASURE_OUTCOME_OK, authv1.ErasureOutcome_ERASURE_OUTCOME_FAILED
	ack("userdata-local", e1, okO)
	ack("request-media", e1, failO)
	ack("playback-monitor", e1, okO)
	ack("userdata-local", e2, okO)

	statusOf := func(id string) *authv1.ErasureStatus {
		t.Helper()
		resp, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{ErasureId: id})
		if err != nil || len(resp.GetErasures()) != 1 {
			t.Fatalf("status(%s) = %v, %v", id, resp, err)
		}
		return resp.GetErasures()[0]
	}
	s1 := statusOf(e1)
	if s1.GetComplete() {
		t.Fatal("e1 complete with request-media FAILED")
	}
	got := map[string]*authv1.ErasureModuleStatus{}
	var order []string
	for _, m := range s1.GetModules() {
		got[m.GetModuleId()] = m
		order = append(order, m.GetModuleId())
	}
	if fmt.Sprint(order) != "[userdata-local request-media playback-monitor]" {
		t.Fatalf("module order = %v; want required first, then others", order)
	}
	if !got["userdata-local"].GetRequired() || got["playback-monitor"].GetRequired() ||
		got["request-media"].GetOutcome() != failO || got["userdata-local"].GetAckedAt() == "" {
		t.Fatalf("modules = %v", s1.GetModules())
	}
	s2 := statusOf(e2)
	if s2.GetComplete() || s2.GetModules()[1].GetOutcome() != authv1.ErasureOutcome_ERASURE_OUTCOME_UNSPECIFIED || s2.GetModules()[1].GetAckedAt() != "" {
		t.Fatalf("e2 = %v; want request-media pending", s2)
	}

	// Complete once every required module's latest ack is OK.
	ack("request-media", e1, okO)
	if !statusOf(e1).GetComplete() {
		t.Fatal("e1 not complete with every required module OK")
	}
	pending, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{PendingOnly: true})
	if err != nil || len(pending.GetErasures()) != 1 || pending.GetErasures()[0].GetErasureId() != e2 {
		t.Fatalf("pending = %v, %v; want only e2", pending, err)
	}
	// A later FAILED ack makes it pending again.
	ack("request-media", e1, failO)
	if statusOf(e1).GetComplete() {
		t.Fatal("latest FAILED ack must reopen the erasure")
	}

	// Tenant scope.
	_, err = srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{ErasureId: eForeign})
	requireCode(t, err, codes.NotFound)
	all, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{})
	if err != nil || len(all.GetErasures()) != 2 {
		t.Fatalf("all = %v, %v; want this tenant's 2", all, err)
	}
	// Paging.
	page, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{PageSize: 1})
	if err != nil || len(page.GetErasures()) != 1 || page.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %v, %v", page, err)
	}
	page2, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{PageSize: 1, PageToken: page.GetNextPageToken()})
	if err != nil || len(page2.GetErasures()) != 1 || page2.GetNextPageToken() != "" || page2.GetErasures()[0].GetErasureId() == page.GetErasures()[0].GetErasureId() {
		t.Fatalf("page 2 = %v, %v", page2, err)
	}
	_, err = srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{PageSize: 1, PageToken: page.GetNextPageToken(), PendingOnly: true})
	requireCode(t, err, codes.InvalidArgument)
	_, err = srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{PageSize: 501})
	requireCode(t, err, codes.InvalidArgument)
	_, err = srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{ErasureId: "er_unknown"})
	requireCode(t, err, codes.NotFound)
}

func TestParseModuleList(t *testing.T) {
	got := ParseModuleList(" userdata-local, ,request-media,userdata-local ,")
	if fmt.Sprint(got) != "[userdata-local request-media]" {
		t.Fatalf("ParseModuleList = %v", got)
	}
	if ParseModuleList("") != nil {
		t.Fatal("empty list")
	}
}
