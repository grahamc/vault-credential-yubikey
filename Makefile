GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-auth-yubikey cmd/vault-plugin-auth-yubikey/main.go
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o attest cmd/attest/main.go

start:
	vault server -log-level=trace -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault auth enable -path=yubikey-auth vault-plugin-auth-yubikey

clean:
	rm -f ./vault/plugins/vault-plugin-auth-yubikey

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
