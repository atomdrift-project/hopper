.PHONY: build test clean deploy deploy-linux deploy-freebsd rollout-replica-bastille replica rebuild-replica diagnose-replica promote-replica install-precommit help

DATA_DIR  ?= /data/samples
DB        ?= postgres://hopper@hopper-db/hopper?sslmode=disable
SOURCE    ?= harvest
DASH_ADDR ?= 0.0.0.0:8081
# Linux atomscan worker slots and RSS cap in GB, forwarded to the systemd
# deploy script as --workers and --max-memory-gb.
#
# These carry real values rather than 0 because a setting that lives only in
# the generated unit file is silently lost on the next bare `make deploy` —
# which is how the swap cap regressed once already, and how --workers 60 came
# within one deploy of dropping to 40 on 2026-08-01. Override per-host on the
# invocation.
#
# Sized for nazgul: 128 cores, 125 GB RAM, hopper.service MemoryMax=96G.
# MAX_MEMORY_GB must stay under (hopper.service MemoryMax / rssKillFactor):
# 1.25x this value is where the liveness watchdog kills, and it has to land
# below the cgroup limit or the kernel OOM killer wins the race instead —
# 72 x 1.25 = 90G, under the 96G cap. Raising it means raising that cap and
# cutting ARC c_max to stay inside physical RAM.
WORKERS       ?= 60
MAX_MEMORY_GB ?= 72
# Native FreeBSD runs the worker as a separate rc.d service. Let Scan choose
# its RSS admission threshold automatically unless a host needs an override.
FREEBSD_WORKERS       ?= 96
FREEBSD_MAX_MEMORY_GB ?= 0
SCAN_DIR      ?= ../scan
LLM           ?= http://10.9.8.149:8000/v1

help:
	@echo "Available targets:"
	@echo "  make build                  Build the hopper binary"
	@echo "  make test                   Run tests"
	@echo "  make lint                   Run linters"
	@echo "  make clean                  Clean build artifacts"
	@echo "  make install-precommit      Install the git pre-commit hook (test + lint + go.mod)"
	@echo "  make deploy                 Install Hopper and its separate scan worker"
	@echo "                              (DATA_DIR=$(DATA_DIR) DB=... SOURCE=$(SOURCE) DASH_ADDR=$(DASH_ADDR)"
	@echo "                               Linux: WORKERS=$(WORKERS) MAX_MEMORY_GB=$(MAX_MEMORY_GB)"
	@echo "                               FreeBSD: WORKERS=$(FREEBSD_WORKERS) MAX_MEMORY_GB=$(FREEBSD_MAX_MEMORY_GB) SCAN_DIR=$(SCAN_DIR))"
	@echo "  make rollout-replica-bastille Deploy a Bastille jail as a logical replica"
	@echo "                              (RUN=<jail> REMOTE_HOST=hopper-db SUBSCRIPTION=...;"
	@echo "                               REBUILD=true for a destructive re-copy of a wedged jail,"
	@echo "                               BULK_MAINT_MEM=8GB to speed index rebuilds on a big box)"
	@echo "  make replica                Configure local postgres as a logical replica of the"
	@echo "                              upstream hopper DB (idempotent + resumable; reads ~/.pgpass)"
	@echo "  make rebuild-replica        Tear down a wedged replica (invalidated slot or"
	@echo "                              apply conflict) and rebuild from scratch —"
	@echo "                              TRUNCATEs + full re-copy (FORCE=true)"
	@echo "  make diagnose-replica       Dump replication status from both sides (read-only)"
	@echo "  make promote-replica        Turn the local replica into a standalone primary"
	@echo "                              (writes must already be stopped; idempotent)"

build:
	CGO_ENABLED=1 go build -o hopper -ldflags="-s -w" ./cmd/hopper

install-precommit:
	cp scripts/pre-commit $(shell git rev-parse --git-path hooks)/pre-commit
	chmod +x $(shell git rev-parse --git-path hooks)/pre-commit
	@echo "Pre-commit hook installed."

test:
	go test ./...

deploy:
	@case "$$(uname -s)" in \
		FreeBSD) $(MAKE) deploy-freebsd ;; \
		*)       $(MAKE) deploy-linux ;; \
	esac

deploy-linux:
	DATA_DIR='$(DATA_DIR)' DB='$(DB)' SOURCE='$(SOURCE)' \
	DASH_ADDR='$(DASH_ADDR)' WORKERS='$(WORKERS)' \
	MAX_MEMORY_GB='$(MAX_MEMORY_GB)' \
	./scripts/master/linux-systemd.sh

deploy-freebsd:
	DATA_DIR='$(DATA_DIR)' DB='$(DB)' SOURCE='$(SOURCE)' \
	DASH_ADDR='$(DASH_ADDR)' WORKERS='$(FREEBSD_WORKERS)' \
	MAX_MEMORY_GB='$(FREEBSD_MAX_MEMORY_GB)' SCAN_DIR='$(SCAN_DIR)' LLM='$(LLM)' \
		./scripts/master/freebsd.sh

rollout-replica-bastille:
	@./scripts/replica/freebsd-bastille.sh "$(RUN)"

replica: build
	@HOPPER='$(CURDIR)/hopper' ./scripts/replica/setup.sh

rebuild-replica: build
	@HOPPER='$(CURDIR)/hopper' ./scripts/replica/rebuild.sh

diagnose-replica:
	@./scripts/replica/diagnose.sh

promote-replica:
	@./scripts/replica/promote.sh

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
