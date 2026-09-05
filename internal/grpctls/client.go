package grpctls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ClientDialOptions returns gRPC dial options for connecting to auth-local.
// Honors MUXCORE_INSECURE_DISABLE_TLS / MUXCORE_GRPC_INSECURE for plaintext dev.
// Otherwise uses MUXCORE_TLS_* or AUTH_TLS_* client certificate paths when set.
func ClientDialOptions() ([]grpc.DialOption, error) {
	if InsecureAllowed() {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}

	certFile := firstNonEmpty(os.Getenv(envAuthTLSCert), os.Getenv(envTLSCert))
	keyFile := firstNonEmpty(os.Getenv(envAuthTLSKey), os.Getenv(envTLSKey))
	caFile := firstNonEmpty(os.Getenv(envAuthTLSCA), os.Getenv(envTLSCA))

	if certFile == "" || keyFile == "" {
		// Session-token clients may dial without presenting a client cert when the
		// server uses VerifyClientCertIfGiven; skip mTLS credentials.
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if caFile != "" {
			pool, err := loadCertPool(caFile)
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client TLS cert/key: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	serverName := strings.TrimSpace(os.Getenv("AUTH_TLS_SERVER_NAME"))
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}

// ClientTLSConfigForTest loads or skips TLS for integration tests.
func ClientTLSConfigForTest() (*tls.Config, error) {
	if InsecureAllowed() {
		return nil, nil
	}
	opts, err := ClientDialOptions()
	if err != nil {
		return nil, err
	}
	for _, o := range opts {
		_ = o
	}
	caFile := firstNonEmpty(os.Getenv(envAuthTLSCA), os.Getenv(envTLSCA))
	if caFile == "" {
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, nil
	}
	pool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// VerifyPool is exported for tests that need the CA pool.
func VerifyPool(caFile string) (*x509.CertPool, error) {
	return loadCertPool(caFile)
}
