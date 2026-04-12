.PHONY: build test clean rollout-bastille sync-db help

# Remote PostgreSQL host — used by sync-db for logical replication.
REMOTE_DB_HOST ?= hopper
REMOTE_DB_USER ?= hopper
REMOTE_DB_NAME ?= hopper
LOCAL_DB_NAME ?= hopper

help:
	@echo "Available targets:"
	@echo "  make build                  Build the hopper binary"
	@echo "  make test                   Run tests"
	@echo "  make lint                   Run linters"
	@echo "  make clean                  Clean build artifacts"
	@echo "  make rollout-bastille       Deploy to Bastille jails (BUILD=build RUN=hopper [DB_ONLY=1])"
	@echo "  make sync-db                Set up logical replication from remote hopper DB"
	@echo "                              (one-time; after this, local DB auto-syncs in real time)"

build:
	CGO_ENABLED=1 go build -o hopper -ldflags="-s -w" ./cmd/hopper

test:
	go test ./...

BUILD ?= build
RUN ?= hopper

rollout-bastille:
	@if [ -n "$(DB_ONLY)" ]; then \
		DB_ONLY=1 ./hacks/rollout-bastille.sh "" "$(RUN)"; \
	else \
		./hacks/rollout-bastille.sh "$(BUILD)" "$(RUN)"; \
	fi

sync-db:
	@echo "==> Setting up logical replication: $(REMOTE_DB_HOST) → localhost"
	@echo "    Remote must have the hopper_training publication (run make rollout-bastille first)."
	@echo ""
	@# Ensure local postgres is running
	@pg_isready -q 2>/dev/null || { echo "Local PostgreSQL is not running. Start it first:"; \
		echo "  sudo systemctl start postgresql"; exit 1; }
	@# Create local database + hopper role if needed
	@psql -U postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$(REMOTE_DB_USER)'" 2>/dev/null | grep -q 1 || \
		createuser -U postgres $(REMOTE_DB_USER) 2>/dev/null || true
	@createdb -U postgres -O $(REMOTE_DB_USER) $(LOCAL_DB_NAME) 2>/dev/null || true
	@# Create the samples table via hopper init if the binary is available
	@if command -v hopper >/dev/null 2>&1; then \
		echo "==> Running hopper init to create schema"; \
		hopper init --db "postgres://$(REMOTE_DB_USER)@localhost/$(LOCAL_DB_NAME)?sslmode=disable"; \
	elif [ -x ./hopper ]; then \
		echo "==> Running ./hopper init to create schema"; \
		./hopper init --db "postgres://$(REMOTE_DB_USER)@localhost/$(LOCAL_DB_NAME)?sslmode=disable"; \
	else \
		echo "WARNING: hopper binary not found — schema must already exist"; \
	fi
	@# Drop existing subscription if present (idempotent re-setup)
	@psql -U $(REMOTE_DB_USER) -d $(LOCAL_DB_NAME) -c \
		"SELECT 1 FROM pg_subscription WHERE subname='hopper_training_sub'" -tA 2>/dev/null | grep -q 1 && \
		psql -U $(REMOTE_DB_USER) -d $(LOCAL_DB_NAME) -c \
			"ALTER SUBSCRIPTION hopper_training_sub DISABLE; ALTER SUBSCRIPTION hopper_training_sub SET (slot_name = NONE); DROP SUBSCRIPTION hopper_training_sub;" 2>/dev/null || true
	@echo "==> Creating subscription to $(REMOTE_DB_HOST)"
	psql -U $(REMOTE_DB_USER) -d $(LOCAL_DB_NAME) -c "\
		CREATE SUBSCRIPTION hopper_training_sub \
		CONNECTION 'host=$(REMOTE_DB_HOST) dbname=$(REMOTE_DB_NAME) user=$(REMOTE_DB_USER)' \
		PUBLICATION hopper_training \
		WITH (copy_data = true);"
	@echo ""
	@echo "==> Logical replication active!"
	@echo "    Initial table copy is running in the background."
	@echo "    Monitor progress: psql -d $(LOCAL_DB_NAME) -c \"SELECT * FROM pg_stat_subscription\""
	@echo "    Use for training: make train DB=postgres://$(REMOTE_DB_USER)@localhost/$(LOCAL_DB_NAME)"

clean:
	rm -f hopper

# BEGIN: lint-install .
# http://github.com/codeGROOVE-dev/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

LINTERS :=
FIXERS :=

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v2.10.1
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	"$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" ./...

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	"$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix ./...

.PHONY: _lint $(LINTERS)
_lint:
	@exit_code=0; \
	for target in $(LINTERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

.PHONY: fix $(FIXERS)
fix:
	@exit_code=0; \
	for target in $(FIXERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

# END: lint-install .
