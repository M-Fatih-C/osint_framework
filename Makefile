SHELL := /bin/bash

.PHONY: setup smoke clean-runtime clean-runtime-all

setup:
	./scripts/setup_env.sh

smoke:
	./scripts/smoke_test.sh

clean-runtime:
	./scripts/runtime_cleanup.sh

clean-runtime-all:
	./scripts/runtime_cleanup.sh --clean-pycache
