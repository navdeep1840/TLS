# Troubleshooting Guide

## Build Issues

### Error: "clang: No such file or directory"

**Cause**: clang compiler not installed

**Solution**:
```bash
# Run the dependency installer
bash INSTALL_DEPS.sh

# OR install manually:

# Ubuntu/Debian
sudo apt-get install clang llvm

# RHEL/Fedora
sudo dnf install clang llvm

# Arch
sudo pacman -S clang llvm
```

### Error: "fatal error: 'bpf/bpf_helpers.h' file not found"

**Cause**: libbpf development headers not installed

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install libbpf-dev linux-headers-$(uname -r)

# RHEL/Fedora
sudo dnf install libbpf libbpf-devel kernel-devel

# Arch
sudo pacman -S libbpf linux-headers
```

### Error: "unknown type name '__wsum'" or "BPF_MAP_TYPE_RINGBUF undeclared"

**Cause**: Incomplete vmlinux.h file

**Solution**: The vmlinux.h has been updated with required definitions. If you still see this error:

```bash
# Regenerate vmlinux.h from your kernel (requires bpftool)
make vmlinux

# OR update manually - the file should already include these types
```

### Error: "Must specify a BPF target arch via __TARGET_ARCH_xxx"

**Cause**: Architecture macro not defined properly

**Solution**: This has been fixed in the code. If you still see it, ensure the first line of `bpf/tls_probe.c` is:
```c
#define __TARGET_ARCH_x86_64 1
```

### Error: "BTF is required, but could not find a suitable source"

**Cause**: Kernel doesn't support BTF

**Check BTF support**:
```bash
ls -l /sys/kernel/btf/vmlinux
```

**Solution**:
1. Upgrade to kernel 5.8 or later:
   ```bash
   # Ubuntu
   sudo apt-get install --install-recommends linux-generic-hwe-$(lsb_release -sr)
   
   # RHEL/Fedora
   sudo dnf update kernel
   
   # Arch
   sudo pacman -Syu linux
   ```

2. Reboot into new kernel:
   ```bash
   sudo reboot
   ```

3. Verify kernel version:
   ```bash
   uname -r  # Should be 5.8+
   ls -l /sys/kernel/btf/vmlinux  # Should exist
   ```

### Error: "go: command not found"

**Cause**: Go not installed or version too old

**Solution**:
```bash
# Check Go version (need 1.21+)
go version

# Install Go 1.21+
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

## Runtime Issues

### Error: "Permission denied"

**Cause**: eBPF programs require root or CAP_BPF capability

**Solution**:
```bash
# Run with sudo
sudo ./tls-inspector run

# OR grant capabilities (kernel 5.8+)
sudo setcap cap_bpf,cap_perfmon,cap_net_admin=eip ./tls-inspector
./tls-inspector run
```

### Error: "failed to attach to any process"

**Cause**: No target processes (curl/python) running or library not found

**Diagnosis**:
```bash
# Check if target processes are running
sudo ./tls-inspector status

# Check if curl uses OpenSSL
ldd $(which curl) | grep ssl

# Check if python uses OpenSSL
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

**Solution**:
1. The agent will attach system-wide if no processes found
2. Start curl or python in another terminal
3. The agent will capture their traffic

### No events captured

**Diagnosis**:
```bash
# Start inspector in debug mode
# Edit configs/config.yaml and set: log_level: debug
sudo ./tls-inspector run

# In another terminal, generate traffic
curl https://httpbin.org/get
```

**Common causes**:
1. **TLS library mismatch**: Application uses GnuTLS or other non-OpenSSL library
   ```bash
   ldd $(which curl) | grep -E 'ssl|tls|crypto'
   ```

2. **Static linking**: Application has OpenSSL statically linked (rare)
   ```bash
   file $(which curl)
   ```

3. **Wrong library path**: Inspector attached to wrong library
   - Check logs for "Attached to system library: /path/to/libssl.so"
   - Verify this is the library your application uses

**Solution**:
```bash
# For curl with different SSL library
# The inspector currently only supports OpenSSL

# Check what curl uses
curl --version | grep SSL
# Should show: OpenSSL, LibreSSL, or BoringSSL

# If shows GnuTLS or other, install curl with OpenSSL:
sudo apt-get install curl-openssl  # Ubuntu
```

### Events captured but no detections

**Cause**: No sensitive patterns in captured traffic

**Verify**:
```bash
# Test detection rules
./tls-inspector rules test

# Generate test traffic with known secrets
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig" \
  https://httpbin.org/headers
```

### Container ID not showing

**Cause**: Process not running in container

**Verify**:
```bash
# Check if process is in container
cat /proc/$(pgrep curl)/cgroup | grep docker

# Run test in container
docker run --rm -it python:3.11 python3 -c "
import requests
requests.get('https://httpbin.org/get')
"
```

### K8s pod metadata not showing

**Cause**: Environment variables not set in pod

**Solution**: K8s metadata requires these env vars in pod spec:
```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

## Performance Issues

### High CPU usage

**Diagnosis**:
```bash
# Check CPU usage
top -p $(pgrep tls-inspector)
```

**Solution**: Reduce capture size
```yaml
# Edit configs/config.yaml
capture_bytes: 1024  # Reduce from 4096
buffer_size: 65536   # Reduce buffer
```

### Too many events

**Solution**: Filter by process
```bash
# Modify configs/config.yaml to include only specific processes
include_processes:
  - curl  # Remove python if not needed
```

Or filter output:
```bash
sudo ./tls-inspector run | jq 'select(.process == "curl")'
```

## System Compatibility

### Kernel too old

**Check**:
```bash
uname -r
```

**Required**: 5.8+

**Solution**: Upgrade kernel (see BTF error above)

### Architecture not supported

**Current support**: x86_64 only

**Check**:
```bash
uname -m  # Should show: x86_64
```

For ARM64/aarch64, the code needs architecture-specific updates.

### Library incompatibility

**Supported TLS libraries**:
- OpenSSL 1.1.x, 3.x
- LibreSSL
- BoringSSL

**Check**:
```bash
# Check OpenSSL version
openssl version

# Check what library curl uses
ldd $(which curl) | grep ssl
```

**Not supported**:
- GnuTLS
- mbedTLS
- NSS
- WolfSSL

## Testing Issues

### Test script fails

**Run manual test**:
```bash
# Terminal 1
sudo ./tls-inspector run

# Terminal 2  
curl https://httpbin.org/get

# Terminal 1 should show events
```

### Examples don't work

**Python examples**:
```bash
# Install required library
pip3 install requests urllib3

# For httpx
pip3 install httpx

# Run example
python3 examples/python_requests.py
```

**Curl examples**:
```bash
# Make script executable
chmod +x examples/curl_examples.sh

# Run
bash examples/curl_examples.sh
```

## Debugging

### Enable debug logging

Edit `configs/config.yaml`:
```yaml
log_level: debug
```

### Check eBPF programs loaded

```bash
# List BPF programs
sudo bpftool prog list | grep tls

# List BPF maps
sudo bpftool map list

# Dump events (if inspector running)
sudo bpftool map dump name events
```

### Trace SSL calls manually

```bash
# Install bpftrace
sudo apt-get install bpftrace

# Trace SSL_write
sudo bpftrace -e 'uprobe:/usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_write {
  printf("SSL_write called by %s (PID %d)\n", comm, pid);
}'

# In another terminal
curl https://httpbin.org/get
```

### Check process memory maps

```bash
# Find curl PID
CURL_PID=$(pgrep curl)

# Check loaded libraries
cat /proc/$CURL_PID/maps | grep ssl
```

## Getting Help

If issues persist:

1. **Check system requirements**:
   ```bash
   make check
   ```

2. **Review logs** with debug mode enabled

3. **Try minimal test**:
   ```bash
   sudo ./tls-inspector run &
   sleep 2
   curl https://httpbin.org/get
   ```

4. **Check examples**:
   ```bash
   sudo bash examples/test.sh
   ```

5. **Provide details** when seeking help:
   - Kernel version: `uname -r`
   - OS: `cat /etc/os-release`
   - Clang version: `clang --version`
   - Go version: `go version`
   - BTF support: `ls -l /sys/kernel/btf/vmlinux`
   - Error messages and logs

## Common Workarounds

### Can't upgrade kernel

If you're stuck on older kernel without BTF, eBPF won't work. Alternatives:
- Use LD_PRELOAD-based TLS interception
- Use strace (high overhead)
- Use network-level packet capture with TLS keys

### Can't install dependencies

Build on another system with dependencies, copy binary:
```bash
# On build system
make build
tar czf tls-inspector.tar.gz tls-inspector bpf/tls_probe.o configs/ rules/

# On target system
tar xzf tls-inspector.tar.gz
sudo ./tls-inspector run
```

Note: eBPF object may not be portable across kernel versions without CO-RE.
