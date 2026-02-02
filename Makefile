.PHONY: build test lint clean docker-build docker-push help swagger

BINARY_NAME=est-service
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-w -s -X github.com/mabunixda/est-service/version.Version=${VERSION} \
	-X github.com/mabunixda/est-service/version.Commit=${GIT_COMMIT} \
	-X github.com/mabunixda/est-service/version.BuildDate=${BUILD_DATE}"

# Docker configuration
DOCKERFILE=deployments/docker/Dockerfile
REGISTRY?=
IMAGE_NAME?=est-service
GO_VERSION?=$(shell awk '/^go / {print $$2}' go.mod)
ALPINE_VERSION?=3.21
PLATFORMS?=linux/amd64,linux/arm64,linux/arm/v6

ifeq ($(REGISTRY),)
	IMAGE_TAG=$(IMAGE_NAME):$(VERSION)
	IMAGE_LATEST=$(IMAGE_NAME):latest
else
	IMAGE_TAG=$(REGISTRY)/$(IMAGE_NAME):$(VERSION)
	IMAGE_LATEST=$(REGISTRY)/$(IMAGE_NAME):latest
endif

all: clean build

build:
	@echo "Building..."
	@mkdir -p bin
	go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/est-service

openapi:
	@echo "Generating Swagger/OpenAPI documentation..."
	swag init -g cmd/est-service/main.go -o docs --parseDependency --parseInternal

# Unit tests only (fast, no Docker required)
test: test-unit

# Unit tests without race detector (for coverage)
test-unit:
	go test -v -coverprofile=coverage.out ./...

# Integration tests (requires Docker)
test-integration:
	@echo "Running integration tests..."
	go test -v -coverprofile=coverage_integration.out -tags=integration -timeout 5m ./pkg/backend

# All tests including integration
test-all: test-unit test-integration

lint:
	golangci-lint run

fmt: 
	gofmt -s -w .

clean:
	rm -rf bin/
	rm -f coverage.out coverage_integration.out

docker: 
	@echo "Building multi-platform Alpine image: $(IMAGE_TAG)"
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-f $(DOCKERFILE) \
		-t $(IMAGE_TAG) \
		.
