############################
# Builder
############################
FROM golang:1.25 AS builder

# Version metadata (override via --build-arg)
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ARG GOVERSION=1.24.0

# Cross-compile targets (override or set via buildx)
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module cache warmup
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Run unit tests for the secret controller package (runs secret_controller_test.go)
# Avoid -race to prevent QEMU segfaults when building for non-native platforms.
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go test ./controller -count=1 -v

# Build the binary with version metadata
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.date=${DATE}" \
      -o /out/manager ./cmd/main.go

############################
# Runtime
############################
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.title="vault-secret-sync-operator" \
      org.opencontainers.image.description="Kubernetes operator for syncing secrets from Vault" \
      org.opencontainers.image.source="https://github.com/CloudHubCZ/vault-secret-sync-operator" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/manager /manager

ENTRYPOINT ["/manager"]