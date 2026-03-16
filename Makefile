.PHONY: fmt vet test build build-all ci clean

fmt:
	gofmt -w $$(find . -type f -name '*.go')

vet:
	go vet ./...

test:
	go test ./...

build:
	mkdir -p dist
	go build -o dist/gomap ./cmd
	go build -o dist/gomap-assetprobe ./cmd/assetprobe

build-all:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/gomap-linux-amd64 ./cmd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o dist/gomap-linux-arm64 ./cmd
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/gomap-darwin-amd64 ./cmd
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/gomap-darwin-arm64 ./cmd
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/gomap-windows-amd64.exe ./cmd

ci: vet test build

clean:
	rm -rf dist
