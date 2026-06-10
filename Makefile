.PHONY: build test lint clean admin-cli

build:
	go build -o auth-local ./cmd/module

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

admin-cli:
	go build -o authctl ./cmd/authctl

clean:
	rm -f auth-local authctl
	rm -f cmd/module/module
