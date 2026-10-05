package server

import "testing"

func TestMeshIdentityRequiresVerifiedChain(t *testing.T) {
	if cn, ok := meshCallerFromContext(verifiedMeshContext("muxcore")); !ok || cn != "muxcore" {
		t.Fatalf("verified peer rejected: %q %v", cn, ok)
	}
	if cn, ok := meshCallerFromContext(unverifiedMeshContext("muxcore")); ok {
		t.Fatalf("unverified (self-signed) peer with matching CN accepted: %q", cn)
	}
	if _, ok := peerCertCN(unverifiedMeshContext("muxcore")); ok {
		t.Fatal("peerCertCN accepted unverified chain")
	}
}
