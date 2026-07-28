# helper

CARGO ?= cargo

CWD := $(shell pwd)
BUILDDIR := $(CWD)/target
NAME := pingsix

DESTDIR ?=
PREFIX ?= /usr
CONFIGDIR ?= /etc/$(NAME)
BINDIR ?= $(PREFIX)/local/bin

define HELP
usage:
  make clean     => cargo clean
  make fmt       => cargo fmt all
  make checkfmt  => cargo fmt all check
  make clippy    => cargo clippy
  make test      => run test
  make dtest     => run test with debug messages
  make build     => compile the code
  make release   => compile the code with release profile
  make install   => install binary and config files
endef

.PHONY: all
all:
	@$(info $(HELP)) :

.PHONY: clean
clean:
	@$(CARGO) clean

.PHONY: fmt
fmt:
	@$(CARGO) fmt --all

.PHONY: checkfmt
checkfmt:
	@$(CARGO) fmt \
		--all \
		-- \
		--check

.PHONY: clippy
clippy:
	@$(CARGO) clippy \
		--locked \
		--all-targets \
		--all-features \
		-- \
		-D warnings

.PHONY: test
test:
	@$(CARGO) test \
		--locked \
		--all-targets \
		--all-features \
		--verbose

.PHONY: dtest
dtest:
	@$(CARGO) test \
		--locked \
		--all-targets \
		--all-features \
		--verbose \
		-- \
		--nocapture

.PHONY: release
release:
	@$(CARGO) build \
		--release \
		--locked \
		--all-targets \
		--all-features \
		--verbose

.PHONY: build
build:
	@$(CARGO) build \
		--locked \
		--all-targets \
		--all-features \
		--verbose

.PHONY: install
install:
	@mkdir -p $(DESTDIR)/$(CONFIGDIR)
	@mkdir -p $(DESTDIR)/$(BINDIR)
	install -m644 $(CWD)/config.yaml $(DESTDIR)/$(CONFIGDIR)/config.yaml
	install -m755 $(BUILDDIR)/release/$(NAME) $(DESTDIR)/$(BINDIR)/$(NAME)
