# Quick Start Guide

## 5-Minute Setup

### Prerequisites Check

```bash
# 1. Check kernel version (need 5.8+)
uname -r

# 2. Check BTF support
ls -lh /sys/kernel/btf/vmlinux

# 3. Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y clang llvm make golang libbpf-dev linux-headers-$(uname -r)
```

### Build

```bash
cd /app/tls-inspector

# Verify system requirements
make check

# Build everything
make build
```

Expected output:
```
Compiled eBPF program: bpf/tls_probe.o
Built binary: tls-inspector
```

### Run

#### Terminal 1: Start Inspector

```bash
sudo ./tls-inspector run
```

You should see:
```
Loaded 14 detection rules
Loading eBPF program from ./bpf/tls_probe.o
Attached to system library: /usr/lib/x86_64-linux-gnu/libssl.so.3
TLS Inspector started, monitoring traffic...
```

#### Terminal 2: Generate Traffic

```bash
# Test with curl
curl -H "Authorization: Bearer test-token" https://httpbin.org/headers

# Test with Python
python3 examples/python_requests.py
```

#### Terminal 1: See Results

You'll see JSON events like:

```json
{
  "timestamp": "2026-04-14T12:00:00Z",
  "process": "curl",
  "pid": 12345,
  "function": "SSL_write",
  "direction": "egress",
  "plaintext_preview": "GET /headers HTTP/1.1...",
  "detections": ["JWT Token"],
  "severity": "medium"
}
```

## Common Issues

### "Permission denied"
**Solution**: Run with sudo or grant capabilities
```bash
sudo ./tls-inspector run
```

### "No events captured"
**Solution**: Check if target processes are using OpenSSL
```bash
ldd $(which curl) | grep ssl
ldd $(which python3) | grep ssl
```

### "BTF is required"
**Solution**: Your kernel doesn't support BTF. Upgrade to kernel 5.8+
```bash
# Check current kernel
uname -r

# Upgrade (Ubuntu)
sudo apt-get install --install-recommends linux-generic-hwe-$(lsb_release -sr)
```

## Next Steps

1. **Customize config**: Edit `configs/config.yaml`
2. **Add rules**: Edit `rules/default.yaml`
3. **Run tests**: `sudo bash examples/test.sh`
4. **Install system-wide**: `sudo make install`

## Configuration

### Minimal Config

```yaml
# configs/config.yaml
capture_bytes: 4096
rules_path: ./rules/default.yaml
output: stdout
include_processes:
  - curl
  - python
  - python3
```

### Output to File

```yaml
output: both  # stdout and file
output_file: /var/log/tls-events.json
```

### Add Target Process

```yaml
include_processes:
  - curl
  - python
  - python3
  - node      # Monitor Node.js (if using OpenSSL)
```

## Example Commands

```bash
# List detection rules
./tls-inspector rules list

# Test rules with sample data
./tls-inspector rules test

# Check target processes
sudo ./tls-inspector status

# Run with custom config
sudo ./tls-inspector run --config /path/to/config.yaml

# Output to file only
# (edit config.yaml: output: file)
sudo ./tls-inspector run &
tail -f tls-events.json | jq '.'
```

## Detection Rules

### Add Custom Rule

Edit `rules/default.yaml`:

```yaml
- id: my-custom-secret
  name: My Custom Secret
  description: Detects my custom secret format
  severity: high
  enabled: true
  regex:
    - 'myapp_secret_[a-zA-Z0-9]{32}'
  keywords:
    - myapp_token
```

Test it:
```bash
./tls-inspector rules test
```

## Monitoring Containers

The inspector automatically detects Docker and Kubernetes containers:

```bash
# Run app in Docker
docker run -it --rm python:3.11 python3 -c "
import requests
requests.get('https://httpbin.org/get')
"
```

Inspector output will include:
```json
{
  "container_id": "abc123456789",
  "pod_name": "my-pod",
  "namespace": "default",
  ...
}
```

## Integration

### Output to SIEM (JSON Lines)

```bash
sudo ./tls-inspector run | while read line; do
  # Send to your SIEM
  echo "$line" | curl -X POST https://your-siem.com/api/events \
    -H "Content-Type: application/json" \
    -d "$line"
done
```

### Alerting on Critical Detections

```bash
sudo ./tls-inspector run | jq -r 'select(.severity == "critical")'
```

### Filter by Process

```bash
sudo ./tls-inspector run | jq 'select(.process == "curl")'
```

## Performance Tuning

### Low Overhead Mode

```yaml
capture_bytes: 1024      # Capture less data
buffer_size: 65536       # Smaller buffer
```

### High Detail Mode

```yaml
capture_bytes: 8192      # Capture more data
buffer_size: 1048576     # Larger buffer (1MB)
```

## Troubleshooting

### Debug Mode

Edit `configs/config.yaml`:
```yaml
log_level: debug
```

### Check eBPF Programs Loaded

```bash
sudo bpftool prog list | grep tls
sudo bpftool map list
```

### Manually Test OpenSSL Hook

```bash
# Install bpftrace (optional)
sudo apt-get install bpftrace

# Trace SSL_write calls
sudo bpftrace -e 'uprobe:/usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_write { 
  printf("SSL_write called by PID %d\n", pid); 
}'

# In another terminal
curl https://httpbin.org/get
```

## Clean Up

```bash
# Stop inspector
Ctrl+C

# Clean build artifacts
make clean

# Uninstall
sudo make uninstall
```

## Getting Help

1. Check [README.md](README.md) for full documentation
2. See [BUILD.md](BUILD.md) for build troubleshooting
3. Review [DESIGN.md](DESIGN.md) for architecture details
4. Run examples in `examples/` directory

## Security Notice

⚠️ This tool captures plaintext TLS traffic including sensitive data. Use only in authorized environments for security monitoring, incident response, and compliance purposes.
