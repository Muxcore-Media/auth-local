package internal

// IntegrationListenAddr returns the bound gRPC listen address for integration tests.
func IntegrationListenAddr(m *Module) string {
	if m.grpcLis != nil {
		return m.grpcLis.Addr().String()
	}
	return m.grpcAddr
}
