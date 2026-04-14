# Build Instructions

## Prerequisites

### System Requirements

- Linux kernel 5.8 or later with BTF (BPF Type Format) support
- x86_64 architecture (ARM64 support possible with modifications)
- At least 2GB RAM
- Root privileges or CAP_BPF + CAP_PERFMON capabilities

### Required Software

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
  clang \
  llvm \
  gcc \
  make \
  golang-1.21 \
  libbpf-dev \
  linux-headers-$(uname -r) \
  pkg-config
```

#### RHEL/CentOS/Fedora

```bash
sudo dnf install -y \
  clang \
  llvm \
  gcc \
  make \
  golang \
  libbpf \
  libbpf-devel \
  kernel-devel \
  pkg-config
```

#### Arch Linux

```bash
sudo pacman -S \
  clang \
  llvm \
  gcc \
  make \
  go \
  libbpf \
  linux-headers
```

### Verify Prerequisites

```bash
# Check kernel version (need 5.8+)
uname -r

# Check BTF support
ls -lh /sys/kernel/btf/vmlinux

# Check clang
clang --version

# Check Go
go version

# Check for eBPF support
sudo bpftool feature
```

## Building from Source

### 1. Clone or Extract Source

```bash
cd /app/tls-inspector
```

### 2. Check System Requirements

```bash
make check
```

Expected output:
```
Checking system requirements...
5.15.0-generic
✓ BTF support available
✓ clang found: Ubuntu clang version 14.0.0
✓ llvm-strip found
```

### 3. Build

```bash
make build
```

This will:
1. Compile the eBPF C program (`bpf/tls_probe.c`) to `bpf/tls_probe.o`
2. Download Go dependencies
3. Build the Go userspace agent to `tls-inspector` binary

### 4. Verify Build

```bash
# Check eBPF object
ls -lh bpf/tls_probe.o

# Check binary
ls -lh tls-inspector
./tls-inspector --help
```

## Build Variants

### Clean Build

```bash
make clean
make build
```

### Debug Build

For debugging, you can add more verbose output:

```bash
# Edit configs/config.yaml
log_level: debug

# Rebuild
make build
```

### Generate Fresh vmlinux.h

If you have `bpftool` installed:

```bash
make vmlinux
```

This generates kernel type definitions from your running kernel.

## Installation

### System-wide Installation

```bash
sudo make install
```

This installs:
- Binary to `/usr/local/bin/tls-inspector`
- Config to `/etc/tls-inspector/configs/`
- Rules to `/etc/tls-inspector/rules/`

### Uninstall

```bash
sudo make uninstall
```

## Troubleshooting Build Issues

### Issue: "fatal error: 'bpf/bpf_helpers.h' file not found"

**Solution**: Install libbpf development headers

```bash
# Ubuntu/Debian
sudo apt-get install libbpf-dev

# RHEL/Fedora
sudo dnf install libbpf-devel
```

### Issue: "undefined reference to `bpf_object__open'"  

**Solution**: This shouldn't occur as we're using cilium/ebpf (pure Go). If you see this, check your build environment.

### Issue: clang version too old

**Solution**: Install clang 10 or later

```bash
# Ubuntu (install newer clang)
sudo apt-get install clang-14
export CLANG=clang-14
make build
```

### Issue: "BTF is required, but could not find a suitable source"

**Solution**: Your kernel doesn't have BTF support. Options:

1. Upgrade to kernel 5.8+
2. Rebuild kernel with `CONFIG_DEBUG_INFO_BTF=y`
3. Check if BTF is available: `ls /sys/kernel/btf/vmlinux`

### Issue: Go version mismatch

**Solution**: Update Go to 1.21+

```bash
# Download and install Go 1.21+
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```

## Cross-compilation

### Building for Different Architectures

The eBPF program needs to be compiled for the target kernel. For cross-compilation:

```bash
# For ARM64 (aarch64)
CLANG=clang make build ARCH=arm64
```

**Note**: This is experimental and may require additional setup.

## Development Build

For development with faster iteration:

```bash
# Install Go dependencies
make deps

# Run without installing
sudo ./tls-inspector run

# Or use make
make run
```

## Testing the Build

### Quick Test

```bash
# Run automated test
sudo bash examples/test.sh
```

### Manual Test

```bash
# Terminal 1: Start inspector
sudo ./tls-inspector run

# Terminal 2: Generate traffic
curl https://httpbin.org/get
```

You should see JSON events in Terminal 1.

## Build Artifacts

After a successful build:

```
tls-inspector/
├── tls-inspector          # Main binary (~15-20MB)
├── bpf/tls_probe.o        # Compiled eBPF object (~50-100KB)
└── go.sum                 # Go dependency checksums
```

## Dependencies

### Go Modules

Defined in `go.mod`:

- `github.com/cilium/ebpf` v0.12.3 - eBPF library
- `gopkg.in/yaml.v3` v3.0.1 - YAML parsing
- `github.com/spf13/cobra` v1.8.0 - CLI framework

### System Libraries

- `libc` - Standard C library
- `libelf` - ELF file handling (indirect via cilium/ebpf)
- `zlib` - Compression (indirect)

## Next Steps

After building:

1. Review configuration: `configs/config.yaml`
2. Review detection rules: `rules/default.yaml`
3. Run the agent: `sudo ./tls-inspector run`
4. See [README.md](README.md) for usage instructions
