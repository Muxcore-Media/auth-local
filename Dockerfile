FROM golang:1.26-alpine AS builder

# Copy core alongside auth-local so replace directives resolve
# auth-local/go.mod: replace core => ../core
COPY core/ /build/core/
COPY auth-local/ /build/auth-local/

WORKDIR /build/auth-local
RUN go mod download
RUN CGO_ENABLED=0 go build -o /auth-local ./cmd/module

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl
RUN adduser -D -h /data auth
USER auth
WORKDIR /app
COPY --from=builder /auth-local .
EXPOSE 9041
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "curl -sf http://localhost:9041/login > /dev/null 2>&1"]
ENTRYPOINT ["./auth-local"]
