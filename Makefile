BIN     := ./bin/coraza-lsp
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test cover lint clean vscode vim e2e integration fuzz

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/coraza-lsp

test:
	go test -race -count=1 ./...

integration:
	go test -tags integration -race -count=1 ./internal/analysis/...

# Fuzz parser and analyzer for a short burst. Override FUZZTIME to run longer:
#   make fuzz FUZZTIME=2m
FUZZTIME ?= 30s
fuzz:
	go test -run=^$$ -fuzz=FuzzParse   -fuzztime=$(FUZZTIME) ./internal/parser/...
	go test -run=^$$ -fuzz=FuzzAnalyze -fuzztime=$(FUZZTIME) ./internal/analysis/...

cover:
	go test -race -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

clean:
	rm -rf bin coverage.out coverage.html

e2e: build
	go test -v -timeout 120s ./test/e2e/...

vscode: build
	cd editors/vscode && npm install && npm run compile
	@echo ""
	@echo "Binary built and extension compiled. Launch VS Code with:"
	@echo "  code --extensionDevelopmentPath=\"\$$PWD/editors/vscode\" ."
	@echo "Or restart the language server: Cmd+Shift+P → Coraza: Restart Language Server"

vim: build
	nvim --headless -u editors/vim/test/minimal_init.lua \
		-c "PlenaryBustedDirectory editors/vim/test/spec {minimal_init='editors/vim/test/minimal_init.lua'}" \
		+qa

.DEFAULT_GOAL := build
