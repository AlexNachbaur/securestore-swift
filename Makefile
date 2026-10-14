# One entry point for the checks every change must pass. `make check` is what AGENTS.md,
# CONTRIBUTING.md, and the PR template mean by "the checks"; CI runs the same commands on every
# platform.

SOURCES := Sources Tests Package.swift

.PHONY: check build test lint format

check: lint build test

build:
	swift build

# On Apple platforms this exercises the real Keychain, scoped to a unique service per run.
test:
	swift test

lint:
	swift format lint --strict --recursive $(SOURCES)

format:
	swift format --in-place --recursive $(SOURCES)
