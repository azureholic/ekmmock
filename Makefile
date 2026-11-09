# EkmMock developer targets (spec 11.2). The PowerShell twin for Windows is scripts/dev.ps1 (same target names).
#
#   make dev          generate a test PKI, init a data folder, start the server with --dev (sample keys aes-key-1 / rsa-key-1, fake Managed HSM client trusted)
#   make build        dotnet build -warnaserror
#   make test         dotnet test
#   make image        build the container image (deploy/docker/Dockerfile) as ekmmock:local
#   make compose-up   start the dev stack (docker compose -f deploy/docker/compose.dev.yaml up -d --build, then waits for the seeding and a healthy server)
#   make conformance  run `ekmmock test conformance` inside the dev stack's container (report: ./out/conformance-report.json)
#   make conformance-host   the same suite from the host CLI against a running `make dev`
#   make compose-down stop the dev stack and delete its volume
#   make clean        remove build output and ./out
#
# Ports: EKMMOCK_EKM_PORT (default 443 for compose, 8443 for `make dev`) and EKMMOCK_CONSOLE_PORT (default 8080) can be set when the defaults are taken.
# NUGET_SOURCE: restore source for the image build on a network that cannot reach nuget.org (see docs/DECISIONS.md "M9: Docker build and restore").

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE      := docker compose -f deploy/docker/compose.dev.yaml
OUT          := out
DEV          := $(OUT)/dev
CLI_DLL      := src/EkmMock.Cli/bin/Debug/net10.0/ekmmock.dll
CLI          := dotnet $(CLI_DLL)
EKM_PORT     ?= 8443
CONSOLE_PORT ?= 8080
export NUGET_SOURCE

.PHONY: help dev build test image compose-up conformance conformance-host compose-down clean

help:
	@grep -E '^#   make' Makefile | sed 's/^#   //'

build:
	dotnet build EkmMock.sln -warnaserror

test:
	dotnet test EkmMock.sln

image:
	docker build -f deploy/docker/Dockerfile -t ekmmock:local --build-arg NUGET_SOURCE="$(NUGET_SOURCE)" .

dev:
	dotnet build src/EkmMock.Cli/EkmMock.Cli.csproj -warnaserror
	dotnet build src/EkmMock.Server/EkmMock.Server.csproj -warnaserror
	mkdir -p $(DEV)/data/tls
	test -f $(DEV)/pki/root-ca.pem || $(CLI) certs dev --out $(DEV)/pki --fqdn localhost
	$(CLI) init --data $(DEV)/data
	# The server persists an uploaded certificate over its own files: give it copies, so the PKI folder stays what the CLI wrote.
	cp $(DEV)/pki/server.crt $(DEV)/data/tls/live.crt
	cp $(DEV)/pki/server.key $(DEV)/data/tls/live.key
	# Trust the fake Managed HSM client as soon as the console answers (background), then run the server in the foreground.
	( for i in $$(seq 1 90); do \
	    if $(CLI) health --ready --console https://127.0.0.1:$(CONSOLE_PORT) --console-ca $(DEV)/pki/root-ca.pem >/dev/null 2>&1; then \
	      $(CLI) trust import --ns _default --json $(DEV)/pki/mhsm-client.json --console https://127.0.0.1:$(CONSOLE_PORT) --console-ca $(DEV)/pki/root-ca.pem \
	        && echo "EkmMock is ready (sample keys aes-key-1 and rsa-key-1, fake Managed HSM client trusted). In another shell: make conformance-host"; \
	      exit 0; \
	    fi; sleep 1; \
	  done; echo "the console did not come up" >&2 ) &
	Data__Path=$(DEV)/data \
	EKMMOCK_MASTER_KEY_FILE=$(DEV)/data/master.key \
	Tls__CertFile=$(DEV)/data/tls/live.crt Tls__KeyFile=$(DEV)/data/tls/live.key \
	Endpoints__Ekm__Url=https://0.0.0.0:$(EKM_PORT) Endpoints__Console__Url=https://127.0.0.1:$(CONSOLE_PORT) \
	Dev__SeedSampleKeys=true EKMMOCK_ALLOW_KEY_IMPORT=true EKMMOCK_ENABLE_FAULTS=true \
	dotnet run --project src/EkmMock.Server --no-build -- --dev

compose-up:
	$(COMPOSE) up -d --build
	# `up --wait` fails on some Compose versions because the one-shot containers exit, so wait for them explicitly: dev-seed ends only after dev-init and a healthy server.
	@code=$$(docker wait ekmmock-dev-seed); \
	if [ "$$code" != "0" ]; then echo "dev-seed failed (exit code $$code)" >&2; $(COMPOSE) logs dev-init dev-seed >&2; exit 1; fi
	@for i in $$(seq 1 90); do \
	  if [ "$$(docker inspect -f '{{.State.Health.Status}}' ekmmock-dev)" = "healthy" ]; then echo "EkmMock is up (healthy), sample keys aes-key-1 and rsa-key-1, fake Managed HSM client trusted."; exit 0; fi; \
	  sleep 1; \
	done; echo "ekmmock did not become healthy" >&2; $(COMPOSE) logs ekmmock >&2; exit 1

# The suite from the host against `make dev` (the CLI runs on the host, so it needs the .NET SDK).
conformance-host:
	mkdir -p $(OUT)
	$(CLI) test conformance \
	  --url https://localhost:$(EKM_PORT) --client-cert $(DEV)/pki/client.crt --client-key $(DEV)/pki/client.key --ca $(DEV)/pki/root-ca.pem \
	  --alt-client-cert $(DEV)/pki/client-wrong-cn.crt --alt-client-key $(DEV)/pki/client-wrong-cn.key \
	  --rogue-client-cert $(DEV)/pki/client-untrusted-ca.crt --rogue-client-key $(DEV)/pki/client-untrusted-ca.key \
	  --replacement-server-cert $(DEV)/pki/server-replacement.crt --replacement-server-key $(DEV)/pki/server-replacement.key \
	  --console https://127.0.0.1:$(CONSOLE_PORT) --console-ca $(DEV)/pki/root-ca.pem --allow-disruptive --report $(OUT)/conformance-report.json

compose-down:
	$(COMPOSE) down -v

conformance:
	mkdir -p $(OUT)
	$(COMPOSE) exec -T ekmmock ekmmock test conformance \
	  --url https://localhost:8443 --client-cert /data/dev-pki/client.crt --client-key /data/dev-pki/client.key --ca /data/dev-pki/root-ca.pem \
	  --alt-client-cert /data/dev-pki/client-wrong-cn.crt --alt-client-key /data/dev-pki/client-wrong-cn.key \
	  --rogue-client-cert /data/dev-pki/client-untrusted-ca.crt --rogue-client-key /data/dev-pki/client-untrusted-ca.key \
	  --replacement-server-cert /data/dev-pki/server-replacement.crt --replacement-server-key /data/dev-pki/server-replacement.key \
	  --console https://127.0.0.1:8080 --console-ca /data/dev-pki/root-ca.pem --allow-disruptive --report /data/reports/conformance-report.json
	$(COMPOSE) cp ekmmock:/data/reports/conformance-report.json $(OUT)/conformance-report.json

clean:
	dotnet clean EkmMock.sln -v q || true
	rm -rf $(OUT)
