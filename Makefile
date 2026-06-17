# Common developer tasks. Run `make check` before pushing.
CARGO ?= cargo
UI := app/kvm-desktop/ui
APP := app/kvm-desktop

.PHONY: check test lint fmt fmt-check deny run-cli ui-install ui-build ui-check app-dev app-build clean

check: fmt-check lint test ## fmt + clippy + tests (the CI gate)

test: ## Run the full Rust test suite
	$(CARGO) test --workspace

lint: ## Clippy with warnings denied
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt: ## Format all Rust code
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

deny: ## License + advisory audit
	$(CARGO) deny check

run-cli: ## Run the headless daemon
	$(CARGO) run -p kvm-cli

ui-install:
	pnpm -C $(UI) install

ui-build: ui-install ## Build the SvelteKit frontend
	pnpm -C $(UI) build

ui-check: ui-install ## Type-check the frontend
	pnpm -C $(UI) check

app-dev: ui-build ## Run the desktop app in dev mode
	pnpm -C $(APP) install && pnpm -C $(APP) tauri dev

app-build: ui-build ## Build the desktop bundle for this OS
	pnpm -C $(APP) install && pnpm -C $(APP) tauri build

clean:
	$(CARGO) clean
