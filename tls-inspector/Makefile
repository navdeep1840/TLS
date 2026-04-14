.PHONY: all build clean vmlinux generate test

CLANG ?= clang
LLC ?= llc
GO ?= go
BPFTOOL ?= bpftool

BPF_SOURCE = bpf/tls_probe.c
BPF_OBJ = bpf/tls_probe.o
BINARY = tls-inspector

CFLAGS := -O2 -g -Wall -Werror
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I./bpf

all: build

# Generate vmlinux.h if bpftool is available
vmlinux:
	@if command -v $(BPFTOOL) > /dev/null; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; \
		echo "Generated vmlinux.h"; \
	fi

# Compile eBPF program
$(BPF_OBJ): $(BPF_SOURCE)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Compiled eBPF program: $@"

# Build Go binary
build: $(BPF_OBJ)
	$(GO) mod download
	$(GO) build -o $(BINARY) ./cmd/agent
	@echo "Built binary: $(BINARY)"

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Run tests
test:
	$(GO) test -v ./...

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ) $(BINARY)
	rm -f tls-events.json

# Install to /usr/local/bin
install: build
	sudo cp $(BINARY) /usr/local/bin/
	sudo mkdir -p /etc/tls-inspector
	sudo cp -r configs /etc/tls-inspector/
	sudo cp -r rules /etc/tls-inspector/
	@echo "Installed to /usr/local/bin/$(BINARY)"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(BINARY)
	sudo rm -rf /etc/tls-inspector

# Run the agent
run: build
	sudo ./$(BINARY) run

# Check kernel requirements
check:
	@echo "Checking system requirements..."
	@uname -r
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "✓ BTF support available"; \
	else \
		echo "✗ BTF support not found (kernel 5.8+ required)"; \
	fi
	@if command -v clang > /dev/null; then \
		echo "✓ clang found: $$(clang --version | head -n1)"; \
	else \
		echo "✗ clang not found"; \
	fi
	@if command -v llvm-strip > /dev/null; then \
		echo "✓ llvm-strip found"; \
	else \
		echo "✗ llvm-strip not found"; \
	fi
