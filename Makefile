# Jalon — build et cross-compilation (CGO désactivé : binaires statiques).
# Même socle qu'Arpent et Aplomb.

BINARY   := jalon
PKG      := ./cmd/jalon
DIST     := dist
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
LDFLAGS  := -s -w -X github.com/maxb1906/jalon/internal/model.Version=$(VERSION)
GOFLAGS  := -trimpath
PLATFORMS := windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

export CGO_ENABLED := 0

.PHONY: all build test vet fmt fmt-check build-all windows clean $(PLATFORMS)

all: fmt-check vet test build-all

## build : binaire pour la machine courante dans dist/
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(PKG)

test:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...
	GOOS=darwin go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "Fichiers non formatés :"; echo "$$out"; exit 1; fi

## windows : cible prioritaire (windows/amd64)
windows: windows/amd64

build-all: $(PLATFORMS)

$(PLATFORMS):
	$(eval OS := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	GOOS=$(OS) GOARCH=$(ARCH) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-$(OS)-$(ARCH)$(if $(filter windows,$(OS)),.exe,) $(PKG)

clean:
	rm -rf $(DIST)
