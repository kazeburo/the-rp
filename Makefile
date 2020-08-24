VERSION=0.0.1
LDFLAGS=-ldflags "-X main.Version=${VERSION}"
GO111MODULE=on

all: the-rp

.PHONY: the-rp

the-rp: main.go httpproxy/*.go upstream/*.go
	go build $(LDFLAGS)  -o the-rp main.go

linux: main.go httpproxy/*.go upstream/*.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o the-rp main.go 

check:
	go test ./...

fmt:
	go fmt ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin master
	goreleaser --rm-dist
