# GHOSTWRITER Makefile
# Engineer: Demiyan Dissanayake | Dexel Software Solutions

BINARY     := ghostwriter
BUILD_DIR  := ./build
CMD        := ./cmd/ghostwriter
VERSION    := 1.0.0
LDFLAGS    := -ldflags "-X main.Version=$(VERSION) -s -w"

.PHONY: all build clean test lint run-example help

all: build

## build: Compile the binary
build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "  ✓ Built: $(BUILD_DIR)/$(BINARY)"

## install: Install to $GOPATH/bin
install:
	go install $(LDFLAGS) $(CMD)
	@echo "  ✓ Installed to $$(go env GOPATH)/bin/$(BINARY)"

## test: Run all unit tests
test:
	go test ./... -v -timeout 30s

## test-short: Run tests without verbose output
test-short:
	go test ./... -timeout 30s

## lint: Run go vet
lint:
	go vet ./...

## clean: Remove build artifacts and local database/reports
clean:
	rm -rf $(BUILD_DIR) ghostwriter.db ./reports
	@echo "  ✓ Cleaned"

## run-example: Ingest example sessions, correlate, and generate HTML report
run-example: build
	@echo ""
	@echo "  Running GHOSTWRITER with example sessions..."
	@echo ""
	$(BUILD_DIR)/$(BINARY) ingest --file examples/sessions.json
	$(BUILD_DIR)/$(BINARY) correlate
	$(BUILD_DIR)/$(BINARY) report --format html
	@echo "  Open reports/ to view the HTML report."

## help: Show this help
help:
	@echo ""
	@echo "  GHOSTWRITER — Makefile targets"
	@echo ""
	@grep -E '^## ' Makefile | sed 's/## /  /'
	@echo ""
