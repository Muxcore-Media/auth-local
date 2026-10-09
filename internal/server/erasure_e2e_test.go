package server

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
	"github.com/Muxcore-Media/core/sdk/go/module/erasure"
	"github.com/Muxcore-Media/core/sdk/go/module/erasure/erasuretest"

	"github.com/Muxcore-Media/auth-local/internal/grpctls"
)

// serveMTLS serves srv with auth-local's real listener TLS configuration
// (grpctls.ServerConfig, AUTH_TLS_* overrides) on 127.0.0.1.
func serveMTLS(t *testing.T, srv *AuthServer, certFile, keyFile, caFile string) string {
	t.Helper()
	for k, v := range map[string]string{
		"MUXCORE_INSECURE_DISABLE_TLS": "", "MUXCORE_GRPC_INSECURE": "", "MUXCORE_DEV_TLS_SKIP": "",
		"AUTH_TLS_CERT": certFile, "AUTH_TLS_KEY": keyFile, "AUTH_TLS_CA": caFile,
	} {
		t.Setenv(k, v)
	}
	cfg, err := grpctls.ServerConfig(t.TempDir())
	if err != nil || cfg == nil {
		t.Fatalf("server TLS config: %v", err)
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	srv.RegisterWithGRPC(gs)
	done := make(chan struct{})
	go func() { defer close(done); _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); <-done })
	return lis.Addr().String()
}

func reconciler(t *testing.T, pki *erasuretest.PKI, owner *erasuretest.Owner, addr string) *erasure.Reconciler {
	t.Helper()
	cert, key := pki.Issue(t, owner.ModuleID())
	r, err := erasure.New(erasure.Config{
		Owner: owner,
		Dialer: &erasure.ProviderDialer{
			Discovery: erasuretest.NewDiscovery(erasuretest.Module("auth-local", addr)),
			CertFile:  cert, KeyFile: key, CAFile: pki.CAFile,
			Getenv: func(string) string { return "" },
		},
		Getenv:      func(string) string { return "" },
		Jitter:      -1,
		AckAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestErasureLedgerWithSDKReconcilerOverMTLS proves the core consumer helper
// (sdk/go/module/erasure v0.6.7) interoperates with this provider: discovery,
// server CN pinning, paging, application, acknowledgement under the verified
// client CN, idempotent re-sweep and admin status, all over real mTLS.
func TestErasureLedgerWithSDKReconcilerOverMTLS(t *testing.T) {
	pki := erasuretest.NewPKI(t)
	srv := newTestServer(t)
	srv.SetErasureConfig(ErasureConfig{Consumers: []string{"userdata-local"}, Required: []string{"userdata-local"}})
	serverCert, serverKey := pki.Issue(t, "auth-local")
	addr := serveMTLS(t, srv, serverCert, serverKey, pki.CAFile)

	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	adminCtx := bearerCtx(t, srv, admin.ID)
	victim := mkUser(t, srv, "victim", "")
	bystander := mkUser(t, srv, "bystander", "")
	var erasureIDs []string
	erasureIDs = append(erasureIDs, eraseVia(t, srv, adminCtx, victim.ID))
	// More tombstones than one page (the reconciler pages by 100; use 2).
	for _, name := range []string{"x1", "x2"} {
		erasureIDs = append(erasureIDs, eraseVia(t, srv, adminCtx, mkUser(t, srv, name, "").ID))
	}

	owner := erasuretest.NewOwner("userdata-local", map[string]int{victim.ID: 3, bystander.ID: 2})
	r := reconciler(t, pki, owner, addr)

	res, err := r.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("first sweep: %v (%+v)", err, res)
	}
	if res.Seen != 3 || res.Applied != 3 || res.Acked != 3 {
		t.Fatalf("first sweep = %+v; want 3 seen/applied/acked", res)
	}
	if owner.Rows(victim.ID) != 0 || owner.Rows(bystander.ID) != 2 {
		t.Fatalf("owner rows: victim %d, bystander %d", owner.Rows(victim.ID), owner.Rows(bystander.ID))
	}
	if !r.Erased(victim.ID) || r.Erased(bystander.ID) {
		t.Fatal("reconciler erased-id view is wrong")
	}
	// Second sweep: acknowledged_by_caller lets it skip; nothing re-applied.
	res, err = r.SweepOnce(context.Background())
	if err != nil || res.Skipped != 3 || res.Applied != 0 || owner.TotalApplyCalls() != 3 {
		t.Fatalf("second sweep = %+v, %v, apply calls %d; want 3 skipped", res, err, owner.TotalApplyCalls())
	}
	for _, id := range erasureIDs {
		st, err := srv.GetUserErasureStatus(adminCtx, &authv1.GetUserErasureStatusRequest{ErasureId: id})
		if err != nil || !st.GetErasures()[0].GetComplete() {
			t.Fatalf("status(%s) = %v, %v; want complete", id, st, err)
		}
		m := st.GetErasures()[0].GetModules()[0]
		if m.GetModuleId() != "userdata-local" || !m.GetRequired() || m.GetOutcome() != authv1.ErasureOutcome_ERASURE_OUTCOME_OK {
			t.Fatalf("module status = %v", m)
		}
	}
}

// TestErasureLedgerRefusesUnlistedConsumerOverMTLS: a mesh module with a valid
// certificate that is not on AUTH_ERASURE_CONSUMERS reads nothing and erases
// nothing; a consumer without a client certificate is unauthenticated.
func TestErasureLedgerRefusesUnlistedConsumerOverMTLS(t *testing.T) {
	pki := erasuretest.NewPKI(t)
	srv := newTestServer(t)
	srv.SetErasureConfig(ErasureConfig{Consumers: []string{"userdata-local"}})
	serverCert, serverKey := pki.Issue(t, "auth-local")
	addr := serveMTLS(t, srv, serverCert, serverKey, pki.CAFile)
	admin := mkUser(t, srv, "admin", "", "admin")
	_ = mkUser(t, srv, "admin2", "", "admin")
	victim := mkUser(t, srv, "victim", "")
	_ = eraseVia(t, srv, bearerCtx(t, srv, admin.ID), victim.ID)

	owner := erasuretest.NewOwner("media-tagging", map[string]int{victim.ID: 4})
	r := reconciler(t, pki, owner, addr)
	if _, err := r.SweepOnce(context.Background()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unlisted consumer sweep = %v; want PermissionDenied", err)
	}
	if owner.Rows(victim.ID) != 4 || owner.TotalApplyCalls() != 0 {
		t.Fatal("an unlisted consumer applied an erasure")
	}

	// TLS without a client certificate.
	caPEM, err := os.ReadFile(pki.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(caPool, "auth-local")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, err = authv1.NewAuthServiceClient(conn).ListUserErasures(context.Background(), &authv1.ListUserErasuresRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no client certificate = %v; want Unauthenticated", err)
	}
}
