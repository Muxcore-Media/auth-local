package server

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"

	authStore "github.com/Muxcore-Media/auth-local/internal/store"
)

// Environment variables configuring the erasure ledger (ADR-0035 §2).
const (
	// EnvErasureConsumers lists the module ids (mesh certificate CNs) that may
	// call ListUserErasures/AckUserErasure. Empty or unset: both fail closed.
	EnvErasureConsumers = "AUTH_ERASURE_CONSUMERS"
	// EnvErasureRequired lists the module ids whose OK acknowledgement
	// completes an erasure (GetUserErasureStatus).
	EnvErasureRequired = "AUTH_ERASURE_REQUIRED"
)

const maxAckCounts = 32

var detailCodeRE = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// ErasureConfig is the ledger configuration.
type ErasureConfig struct {
	// Consumers is the AUTH_ERASURE_CONSUMERS allowlist of module ids.
	Consumers []string
	// Required is AUTH_ERASURE_REQUIRED.
	Required []string
	// TrustCallerIDWithoutTLS admits x-caller-id as the module identity on a
	// plaintext connection. Only the dev profile with the explicit insecure
	// flag sets it (ADR-0017 §2); a TLS connection never falls back to it.
	TrustCallerIDWithoutTLS bool
}

type erasureConfig struct {
	consumers map[string]bool
	required  []string
	devTrust  bool
}

// ParseModuleList splits a comma-separated module id list, trimming blanks and
// dropping duplicates.
func ParseModuleList(v string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// SetErasureConfig installs the ledger configuration. Safe to call while
// serving.
func (s *AuthServer) SetErasureConfig(cfg ErasureConfig) {
	c := &erasureConfig{consumers: map[string]bool{}, devTrust: cfg.TrustCallerIDWithoutTLS}
	for _, m := range cfg.Consumers {
		if m = strings.TrimSpace(m); m != "" {
			c.consumers[m] = true
		}
	}
	seen := map[string]bool{}
	for _, m := range cfg.Required {
		if m = strings.TrimSpace(m); m != "" && !seen[m] {
			seen[m] = true
			c.required = append(c.required, m)
		}
	}
	s.erasure.Store(c)
	if len(c.consumers) == 0 {
		slog.Warn("erasure ledger: " + EnvErasureConsumers + " is empty; ListUserErasures/AckUserErasure deny every caller")
	}
	for _, m := range c.required {
		if !c.consumers[m] {
			slog.Warn("erasure ledger: required module is not an allowed consumer; erasures can never complete", "module", m)
		}
	}
}

func (s *AuthServer) erasureCfg() *erasureConfig {
	if c := s.erasure.Load(); c != nil {
		return c
	}
	return &erasureConfig{consumers: map[string]bool{}}
}

// erasureConsumer authenticates a ledger caller (ADR-0035 §2): the verified
// mesh client certificate CN, which must be on AUTH_ERASURE_CONSUMERS. The
// x-caller-id header is ignored whenever the connection uses TLS. A user
// bearer never substitutes for the certificate and is refused outright.
func (s *AuthServer) erasureConsumer(ctx context.Context) (string, error) {
	cfg := s.erasureCfg()
	module, err := verifiedModule(ctx, cfg.devTrust)
	if err != nil {
		return "", err
	}
	if sessionTokenFromContext(ctx) != "" {
		return "", status.Error(codes.PermissionDenied, "user bearers are not accepted by the erasure ledger")
	}
	if !cfg.consumers[module] {
		return "", status.Error(codes.PermissionDenied, "module may not access the erasure ledger")
	}
	return module, nil
}

func verifiedModule(ctx context.Context, devTrust bool) (string, error) {
	if cn, ok := peerCertCN(ctx); ok {
		return cn, nil
	}
	p, ok := peer.FromContext(ctx)
	if ok && p.AuthInfo != nil {
		if _, isTLS := p.AuthInfo.(credentials.TLSInfo); isTLS {
			return "", status.Error(codes.Unauthenticated, "verified mesh client certificate required")
		}
	}
	// Plaintext connection: only the dev profile trusts x-caller-id.
	if devTrust && ok && p.AuthInfo == nil {
		if md, mdOK := metadata.FromIncomingContext(ctx); mdOK {
			if vals := md.Get(callerIDMetadataKey); len(vals) == 1 {
				if id := strings.TrimSpace(vals[0]); id != "" {
					return id, nil
				}
			}
		}
	}
	return "", status.Error(codes.Unauthenticated, "verified mesh client certificate required")
}

func ledgerError(err error, msg string) error {
	switch {
	case errors.Is(err, authStore.ErrInvalidErasurePage):
		return status.Error(codes.InvalidArgument, "invalid page_size or page_token")
	case errors.Is(err, authStore.ErrErasureNotFound):
		return status.Error(codes.NotFound, "unknown erasure")
	}
	slog.Error("erasure ledger: "+msg, "error", err)
	return sessionManagementError(err, msg)
}

func formatLedgerTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ListUserErasures pages through the whole tombstone ledger (ADR-0035 §2).
func (s *AuthServer) ListUserErasures(ctx context.Context, req *authv1.ListUserErasuresRequest) (*authv1.ListUserErasuresResponse, error) {
	module, err := s.erasureConsumer(ctx)
	if err != nil {
		return nil, err
	}
	entries, next, err := s.store.ListErasures(ctx, module, int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, ledgerError(err, "list erasures failed")
	}
	resp := &authv1.ListUserErasuresResponse{NextPageToken: next}
	for _, e := range entries {
		resp.Erasures = append(resp.Erasures, &authv1.UserErasure{
			ErasureId: e.ErasureID, UserId: e.UserID, TenantId: e.TenantID,
			DeletedAt: formatLedgerTime(e.DeletedAt), AcknowledgedByCaller: e.AcknowledgedByCaller,
		})
	}
	return resp, nil
}

func outcomeName(o authv1.ErasureOutcome) (string, bool) {
	switch o {
	case authv1.ErasureOutcome_ERASURE_OUTCOME_OK:
		return authStore.ErasureOutcomeOK, true
	case authv1.ErasureOutcome_ERASURE_OUTCOME_FAILED:
		return authStore.ErasureOutcomeFailed, true
	case authv1.ErasureOutcome_ERASURE_OUTCOME_UNSUPPORTED:
		return authStore.ErasureOutcomeUnsupported, true
	}
	return "", false
}

func outcomeEnum(name string) authv1.ErasureOutcome {
	switch name {
	case authStore.ErasureOutcomeOK:
		return authv1.ErasureOutcome_ERASURE_OUTCOME_OK
	case authStore.ErasureOutcomeFailed:
		return authv1.ErasureOutcome_ERASURE_OUTCOME_FAILED
	case authStore.ErasureOutcomeUnsupported:
		return authv1.ErasureOutcome_ERASURE_OUTCOME_UNSUPPORTED
	}
	return authv1.ErasureOutcome_ERASURE_OUTCOME_UNSPECIFIED
}

// AckUserErasure records the verified caller's acknowledgement. The request
// has no module field: the acknowledging module is the certificate CN.
func (s *AuthServer) AckUserErasure(ctx context.Context, req *authv1.AckUserErasureRequest) (*authv1.AckUserErasureResponse, error) {
	module, err := s.erasureConsumer(ctx)
	if err != nil {
		return nil, err
	}
	if !authStore.ValidErasureID(req.GetErasureId()) {
		return nil, status.Error(codes.InvalidArgument, "erasure_id is required")
	}
	outcome, ok := outcomeName(req.GetOutcome())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "outcome must be OK, FAILED or UNSUPPORTED")
	}
	if d := req.GetDetailCode(); d != "" && !detailCodeRE.MatchString(d) {
		return nil, status.Error(codes.InvalidArgument, "detail_code must be 1-64 characters from [a-z0-9_.-]")
	}
	if len(req.GetCounts()) > maxAckCounts {
		return nil, status.Error(codes.InvalidArgument, "too many counts")
	}
	for k, v := range req.GetCounts() {
		if !detailCodeRE.MatchString(k) || v < 0 {
			return nil, status.Error(codes.InvalidArgument, "counts keys must match [a-z0-9_.-]{1,64} and values must not be negative")
		}
	}
	if err := s.store.AckErasure(ctx, req.GetErasureId(), module, outcome, req.GetDetailCode(), req.GetCounts()); err != nil {
		return nil, ledgerError(err, "acknowledge erasure failed")
	}
	return &authv1.AckUserErasureResponse{}, nil
}

// GetUserErasureStatus reports per-module completion of the caller's tenant's
// erasures to an administrator (ADR-0026 §2 bearer; no mesh-peer bypass).
func (s *AuthServer) GetUserErasureStatus(ctx context.Context, req *authv1.GetUserErasureStatusRequest) (*authv1.GetUserErasureStatusResponse, error) {
	caller, err := s.requireSessionAdminIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if id := req.GetErasureId(); id != "" && !authStore.ValidErasureID(id) {
		return nil, status.Error(codes.NotFound, "unknown erasure")
	}
	required := s.erasureCfg().required
	statuses, next, err := s.store.ErasureStatuses(ctx, caller.TenantID, req.GetErasureId(), req.GetPendingOnly(),
		required, int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, ledgerError(err, "erasure status failed")
	}
	resp := &authv1.GetUserErasureStatusResponse{NextPageToken: next}
	for _, st := range statuses {
		resp.Erasures = append(resp.Erasures, erasureStatusProto(st, required))
	}
	return resp, nil
}

func erasureStatusProto(st authStore.ErasureStatus, required []string) *authv1.ErasureStatus {
	acks := make(map[string]authStore.ErasureAck, len(st.Acks))
	for _, a := range st.Acks {
		acks[a.ModuleID] = a
	}
	out := &authv1.ErasureStatus{ErasureId: st.ErasureID, DeletedAt: formatLedgerTime(st.DeletedAt), Complete: true}
	isRequired := make(map[string]bool, len(required))
	for _, m := range required {
		isRequired[m] = true
		ms := &authv1.ErasureModuleStatus{ModuleId: m, Required: true}
		if a, ok := acks[m]; ok {
			ms.Outcome, ms.DetailCode, ms.AckedAt = outcomeEnum(a.Outcome), a.DetailCode, a.AckedAt.UTC().Format(time.RFC3339)
		}
		if ms.GetOutcome() != authv1.ErasureOutcome_ERASURE_OUTCOME_OK {
			out.Complete = false
		}
		out.Modules = append(out.Modules, ms)
	}
	var others []string
	for m := range acks {
		if !isRequired[m] {
			others = append(others, m)
		}
	}
	sort.Strings(others)
	for _, m := range others {
		a := acks[m]
		out.Modules = append(out.Modules, &authv1.ErasureModuleStatus{
			ModuleId: m, Outcome: outcomeEnum(a.Outcome), DetailCode: a.DetailCode, AckedAt: a.AckedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// erasureState is embedded in AuthServer.
type erasureState = atomic.Pointer[erasureConfig]
