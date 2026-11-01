#!/bin/sh
# Vet, test and build inside the official golang container - no local Go installation needed.
# The binary is written to dist/nethernet-proxy for the architecture of the machine running
# Docker (so run it on the Raspberry Pi itself to get a Pi binary).
#
#   scripts/docker-build.sh
set -eu

cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
IMAGE="${GO_IMAGE:-golang:1.25}"

mkdir -p dist
docker run --rm \
  -v "$PWD":/src \
  -v nethernet-proxy-gocache:/go \
  -w /src \
  -e CGO_ENABLED=0 \
  -e GOTOOLCHAIN=local \
  -e VERSION="$VERSION" \
  "$IMAGE" \
  sh -c 'go vet ./... && go test ./... && go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o dist/nethernet-proxy ./cmd/nethernet-proxy'

echo "built dist/nethernet-proxy ($VERSION)"
