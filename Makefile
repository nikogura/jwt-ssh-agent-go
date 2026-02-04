.PHONY: lint test build clean check

# Run namedreturns and golangci-lint
lint:
	@echo "Running namedreturns linter..."
	namedreturns ./...
	@echo "Running golangci-lint..."
	golangci-lint run --timeout=5m

# Run tests
test:
	go test -v ./...

# Build the binary
build:
	go build -o jwt-ssh-agent .

# Clean build artifacts
clean:
	rm -f jwt-ssh-agent

# Run all checks (lint + test)
check: lint test
