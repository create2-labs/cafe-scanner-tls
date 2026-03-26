# cafe-scanner-tls

TLS scanner worker extracted from `cafe-discovery`.
This repository is TLS-only (includes `native/` + `pkg/tls` and requires CGO / OQS runtime).

## Run locally

```bash
CGO_ENABLED=1 go run ./cmd/scanner-tls/main.go
```

Defaults:
- `NATS_URL=nats://localhost:4222`
- `SCANNER_HEALTH_PORT=8081`
- `CONFIG_PATH=./config.yaml`

## Build

```bash
CGO_ENABLED=1 go build ./cmd/scanner-tls
```

## Dependency gate (TLS-only)

TLS scanner must keep the OQS + native dependency chain.

```bash
go list -deps ./cmd/scanner-tls | grep -E "pkg/tls|native|internal/tlsscan|internal/scanner/tlsrunner" >/dev/null
```

Expected result: exit code 0 (at least one match).

## Docker

This image is built on OQS base images:
- build: `oleglod/cafe-crypto-backend:build-oqs`
- runtime: `oleglod/cafe-crypto-backend:runtime-oqs`

```bash
docker build -t cafe-scanner-tls:local .
docker run --rm -e NATS_URL=nats://host.docker.internal:4222 cafe-scanner-tls:local
```

## Image publication and versioning

This repository follows the same RC/Release strategy as `cafe-discovery` and `cafe-scanner-wallet`:

- `docker-rc.yml`: builds and pushes `oleglod/cafe-scanner-tls:sha-<short_sha>` (always), plus optional `vX.Y.Z-rc<run_id>`.
- `docker-release.yml`: promotes from `sha-<short_sha>` to `vX.Y.Z` and `latest` using `imagetools create` (no rebuild).

Supported tags:

- `sha-<short_sha>`: source of truth built by RC
- `vX.Y.Z-rc<run_id>`: optional RC convenience tag
- `vX.Y.Z`: final release tag
- `latest`: most recent released version