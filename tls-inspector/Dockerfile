# ─── Stage 1: Build eBPF object + Go binary ──────────────────────────────────
FROM ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        linux-headers-generic \
        libbpf-dev \
        gcc \
        make \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.22.3
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /build

# Cache Go module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Compile eBPF C program
RUN clang \
        -target bpf -mcpu=v2 -O2 \
        -D__TARGET_ARCH_x86=1 \
        -I/usr/include/x86_64-linux-gnu \
        -I./bpf \
        -I/usr/include \
        -g -c bpf/tls_probe.c -o bpf/tls_probe.o \
    && llvm-objcopy \
        --remove-section=.BTF.ext \
        --remove-section=.rel.BTF.ext \
        bpf/tls_probe.o 2>/dev/null || true

# Build Go binary (static, no CGO needed)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o tls-inspector ./cmd/agent


# ─── Stage 2: Minimal runtime image ──────────────────────────────────────────
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Runtime dependencies only: libelf for BPF map loading, ca-certs for HTTPS POSTs
RUN apt-get update && apt-get install -y --no-install-recommends \
        libelf1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy artifacts from builder
COPY --from=builder /build/tls-inspector        ./tls-inspector
COPY --from=builder /build/bpf/tls_probe.o     ./bpf/tls_probe.o
COPY --from=builder /build/configs              ./configs
COPY --from=builder /build/rules                ./rules

# The BPF object is built against the builder kernel headers.
# At runtime the container must mount the HOST /sys and /proc so that:
#   - /sys/kernel/btf/vmlinux  (kernel BTF, required for CO-RE)
#   - /proc                    (process discovery, /proc/*/maps, /proc/*/comm)
# are visible. See the docker run command / docker-compose.yaml.

ENTRYPOINT ["/app/tls-inspector"]
CMD ["run", \
     "--config",   "/app/configs/config.yaml", \
     "--ebpf-obj", "/app/bpf/tls_probe.o"]
