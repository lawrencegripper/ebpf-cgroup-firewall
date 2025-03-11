.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: generate
generate: ## Generate eBPF code using 'go generate' see https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go
	@if [ "$(shell uname)" = "Linux" ]; then \
		go generate ./... ; \
	fi

.PHONY: check-generate
check-generate: generate ## Check if generate target causes any changes.
	@if ! git diff --quiet; then \
		echo "Please run 'make generate' and commit the changes. Note this will need linux host, use codespace"; \
		exit 1; \
	else \
		echo "Generated eBPF up to date"; \
	fi


.PHONY: build
build: generate ## Build the tool
	go build -v -o bin/ebpf-cgroup-firewall ./cmd/main.go

.PHONY: test
test: ## Run the tests
	go test -race -v ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: smoketest
smoketest: build ## Run the smoke test
	./script/smoke-test.sh

.PHONY: soaktest
soaktest: build ## Run the soak test suite (15min duration)
	./script/soak-test.sh

.PHONY: ci
ci: lint test generate smoketest ## Run CI (lint, generate, test, smoketest)
