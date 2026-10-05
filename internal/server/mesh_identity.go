package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// peerCertCN returns the verified TLS client certificate Common Name from the
// gRPC peer, if present. Mesh identity must come from mTLS — never from
// client-supplied metadata alone.
func peerCertCN(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", false
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	// Require a chain verified against the server's ClientCAs; a presented but
	// unverified certificate (e.g. self-signed with a matching CN) is not identity.
	if len(ti.State.PeerCertificates) == 0 || len(ti.State.VerifiedChains) == 0 {
		return "", false
	}
	cn := strings.TrimSpace(ti.State.PeerCertificates[0].Subject.CommonName)
	return cn, cn != ""
}

func meshCallerFromContext(ctx context.Context) (string, bool) {
	cn, ok := peerCertCN(ctx)
	if !ok {
		return "", false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return cn, true
	}
	vals := md.Get(callerIDMetadataKey)
	if len(vals) == 0 {
		return cn, true
	}
	callerID := strings.TrimSpace(vals[0])
	if callerID == "" {
		return cn, true
	}
	if callerID != cn {
		return "", false
	}
	return cn, true
}

// verifiedMeshContext builds a test context with TLS peer identity. For tests only.
func verifiedMeshContext(callerID string) context.Context {
	cert := &x509.Certificate{
		Subject: pkixName(callerID),
	}
	ti := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		},
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: ti})
	md := metadata.Pairs(callerIDMetadataKey, callerID)
	return metadata.NewIncomingContext(ctx, md)
}

func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}

// unverifiedMeshContext presents a matching-CN certificate without a verified chain. For tests only.
func unverifiedMeshContext(callerID string) context.Context {
	cert := &x509.Certificate{Subject: pkixName(callerID)}
	ti := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: ti})
	return metadata.NewIncomingContext(ctx, metadata.Pairs(callerIDMetadataKey, callerID))
}
