VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := nethernet-proxy
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all vet test build dist clean

all: vet test build

vet:
	go vet ./...

test:
	go test ./...

build:
	$(GOBUILD) -o $(BIN) ./cmd/nethernet-proxy

# Static binaries for the usual always-on LAN boxes.
dist:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64          $(GOBUILD) -o dist/$(BIN)-linux-amd64 ./cmd/nethernet-proxy
	GOOS=linux   GOARCH=arm64          $(GOBUILD) -o dist/$(BIN)-linux-arm64 ./cmd/nethernet-proxy
	GOOS=linux   GOARCH=arm   GOARM=7  $(GOBUILD) -o dist/$(BIN)-linux-armv7 ./cmd/nethernet-proxy
	GOOS=linux   GOARCH=arm   GOARM=6  $(GOBUILD) -o dist/$(BIN)-linux-armv6 ./cmd/nethernet-proxy
	GOOS=windows GOARCH=amd64          $(GOBUILD) -o dist/$(BIN)-windows-amd64.exe ./cmd/nethernet-proxy

clean:
	rm -rf dist $(BIN)
