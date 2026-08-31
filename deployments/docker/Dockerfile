# builder stage
FROM --platform=$BUILDPLATFORM golang:1.25.13-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make ca-certificates tzdata

RUN apk update && apk add --no-cache git make patch tzdata ca-certificates && update-ca-certificates

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary with optimizations
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG GOARM=${TARGETVARIANT#v}

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${GOARM} \
    VERSION=${VERSION} GIT_COMMIT=${COMMIT} BUILD_DATE=${BUILD_DATE} \
    make build

# Alpine runtime stage
FROM --platform=$BUILDPLATFORM alpine:3.21 AS final

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata wget && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 est && \
    adduser -D -u 1000 -G est est

# Create directories
RUN mkdir -p /etc/est /var/lib/est && \
    chown -R est:est /etc/est /var/lib/est

# Copy binary from builder
COPY --from=builder /build/bin/est-service /usr/local/bin/est-service

# Switch to non-root userdokcer
USER est:est

WORKDIR /var/lib/est

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verify-certificate -q --spider https://localhost:8443/health || exit 1

EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/est-service"]
CMD ["--config", "/etc/est/est-service.yaml"]