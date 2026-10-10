# Zeal Auth — local dev commands

set shell := ["bash", "-uc"]

# Start dev server with hot reload on port 5020
dev:
    #!/usr/bin/env bash
    set -euo pipefail
    SERVER_PORT=5020 air

# Build binary
build:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p bin
    go build -o bin/auth-server ./cmd/server

# Start Postgres + Redis
up:
    docker compose up -d

# Stop Postgres + Redis
down:
    docker compose down

# Tail container logs
logs:
    docker compose logs -f

# Run database migrations
migrate-up:
    #!/usr/bin/env bash
    set -euo pipefail
    migrate -path migrations -database "${DATABASE_URL:-postgres://auth:auth@localhost:5435/auth?sslmode=disable}" up

# Rollback last migration
migrate-down:
    #!/usr/bin/env bash
    set -euo pipefail
    migrate -path migrations -database "${DATABASE_URL:-postgres://auth:auth@localhost:5435/auth?sslmode=disable}" down 1

# Run all tests
test:
    go test ./... -count=1 -p 1

# Seed dev data: verified test user + two demo clients (AC-3-4)
seed:
    go run ./cmd/seed

# Register one OAuth client; secret printed once: just seed-client <name> <redirect-uri>
seed-client +args:
    go run ./cmd/seed client {{args}}

# Run all tests with verbose output
test-verbose:
    go test ./... -v -count=1 -p 1

# Run tests with race detector
test-race:
    go test ./... -race -count=1 -p 1

# Run integration tests (requires running DB + Redis)
test-integration:
    go test ./internal/handler/ -run "TestE2E" -v -count=1

# Run E2E tests with Playwright (starts real server, real browser)
test-e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    npx playwright test

# Generate coverage report
test-cover:
    #!/usr/bin/env bash
    set -euo pipefail
    go test ./... -coverprofile=coverage.out
    go tool cover -html=coverage.out -o coverage.html
    echo "Report: coverage.html"

# Lint
lint:
    golangci-lint run ./...

# Clean build artifacts + docker volumes
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf bin/ coverage.out coverage.html
    docker compose down -v
