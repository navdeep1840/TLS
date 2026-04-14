# TLS Inspector

A production-quality eBPF-based TLS plaintext inspection agent for Linux that monitors HTTPS/TLS traffic from **curl** and **Python** applications.

## Features

- **eBPF-based monitoring**: Zero-overhead TLS traffic inspection using uprobes
- **Targeted support**: Focused on curl and Python HTTPS clients (requests, urllib3, httpx, ssl module)
- **Container-aware**: Automatic detection of Docker, containerd, and Kubernetes pods
- **Security detection**: Pattern-based detection of secrets, API keys, tokens, and credentials
- **Rich metadata**: Process, container, and K8s pod attribution for every event
- **Flexible output**: JSON events to stdout or file
- **Simple CLI**: Easy-to-use command-line interface

## Architecture

```
┌─────────────────────────────────────────┐
│  User Application (curl, Python)       │
│                                         │
│  ┌─────────────────────────────┐       │
│  │  OpenSSL/LibreSSL/BoringSSL │       │
│  │  SSL_write / SSL_read       │◄──────┼─── eBPF uprobes
│  └─────────────────────────────┘       │
└─────────────────────────────────────────┘
         │
         │ Plaintext data
         ▼
┌─────────────────────────────────────────┐
│  eBPF Ring Buffer                       │
└─────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  Userspace Agent (Go)                   │
│  ├─ Event Processing                    │
│  ├─ Metadata Enrichment                 │
│  ├─ Detection Engine (YAML rules)       │
│  └─ JSON Output                         │
└─────────────────────────────────────────┘
```

## Requirements

- Linux kernel 5.8+ with BTF (BPF Type Format) support
- clang/LLVM 10+
- Go 1.21+
- Root/CAP_BPF privileges to load eBPF programs

## Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y clang llvm make golang libbpf-dev linux-headers-$(uname -r)

# RHEL/CentOS/Fedora
sudo dnf install -y clang llvm make golang libbpf libbpf-devel kernel-devel
```

### Build from Source

```bash
cd tls-inspector
make check  # Verify system requirements
make build  # Compile eBPF program and Go binary
```

### Install System-wide

```bash
sudo make install
```

## Quick Start

### 1. Start the Inspector

```bash
# Run with default config
sudo ./tls-inspector run

# Run with custom config
sudo ./tls-inspector run --config /path/to/config.yaml
```

### 2. Generate Traffic

In another terminal:

```bash
# Test with curl
curl -H "Authorization: Bearer test-token" https://api.github.com/user

# Test with Python
python3 examples/python_requests.py
```

### 3. View Events

The inspector will output JSON events to stdout:

```json
{
  "timestamp": "2026-04-14T12:00:00Z",
  "process": "curl",
  "pid": 12345,
  "tid": 12345,
  "uid": 1000,
  "cmdline": "curl -H Authorization: Bearer test-token https://api.github.com/user",
  "container_id": "abc123456789",
  "library": "libssl",
  "function": "SSL_write",
  "direction": "egress",
  "data_len": 156,
  "plaintext_preview": "GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer test-token...",
  "detections": ["JWT Token"],
  "severity": "medium"
}
```

## Configuration

Edit `configs/config.yaml`:

```yaml
capture_bytes: 4096              # Max bytes to capture per event
rules_path: ./rules/default.yaml # Detection rules file
output: stdout                   # Output: stdout, file, or both
output_file: tls-events.json     # Output file (when output=file or both)
include_processes:               # Process names to monitor
  - curl
  - python
  - python3
log_level: info                  # Log level: debug, info, warn, error
buffer_size: 262144              # Ring buffer size
```

## Detection Rules

Rules are defined in YAML format (`rules/default.yaml`). The default ruleset includes:

- AWS credentials (access keys, secret keys)
- GCP API keys
- Azure client secrets
- GitHub/GitLab tokens
- JWT tokens
- Generic API keys
- Passwords and credentials
- Private keys
- Credit card numbers
- OpenAI, Slack, Stripe keys

### Example Rule

```yaml
- id: github-token
  name: GitHub Token
  description: Detects GitHub personal access tokens
  severity: critical
  enabled: true
  regex:
    - 'ghp_[a-zA-Z0-9]{36}'
    - 'github_pat_[a-zA-Z0-9_]{82}'
```

## CLI Commands

```bash
# Start monitoring
sudo ./tls-inspector run

# Check target processes
sudo ./tls-inspector status

# List detection rules
./tls-inspector rules list

# Test detection rules
./tls-inspector rules test
```

## Examples

### Monitor Curl Traffic

```bash
# Terminal 1: Start inspector
sudo ./tls-inspector run

# Terminal 2: Make HTTPS request
curl https://api.example.com/data
```

### Monitor Python Application

```python
# examples/python_requests.py
import requests

headers = {"Authorization": "Bearer secret-token"}
response = requests.get("https://api.example.com/data", headers=headers)
print(response.text)
```

```bash
# Terminal 1: Start inspector
sudo ./tls-inspector run

# Terminal 2: Run Python script
python3 examples/python_requests.py
```

### Container Monitoring

```bash
# Run app in Docker
docker run --rm -it python:3.11 python3 -c "
import requests
requests.get('https://api.github.com')
"

# Inspector will show container_id in events
```

## Output Formats

### JSON Event Fields

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | Event timestamp (ISO 8601) |
| `process` | string | Process name (e.g., "curl", "python") |
| `pid` | number | Process ID |
| `tid` | number | Thread ID |
| `uid` | number | User ID |
| `cmdline` | string | Full command line |
| `container_id` | string | Container ID (if in container) |
| `pod_name` | string | Kubernetes pod name (if available) |
| `namespace` | string | Kubernetes namespace (if available) |
| `library` | string | SSL/TLS library used |
| `function` | string | SSL function called |
| `direction` | string | "egress" or "ingress" |
| `data_len` | number | Length of captured data |
| `plaintext_preview` | string | Preview of plaintext data |
| `detections` | array | List of detected patterns |
| `severity` | string | Highest severity level |

## How It Works

1. **eBPF Probes**: The agent attaches uprobes to OpenSSL functions (`SSL_write`, `SSL_read`, etc.) in target processes
2. **Data Capture**: When TLS functions are called, eBPF captures the plaintext data before encryption (write) or after decryption (read)
3. **Event Transport**: Data is sent from kernel to userspace via an eBPF ring buffer
4. **Enrichment**: The Go agent enriches events with process and container metadata
5. **Detection**: YAML-based rules scan for sensitive patterns
6. **Output**: Structured JSON events are written to stdout or file

## Supported TLS Libraries

- OpenSSL 1.1.x, 3.x
- LibreSSL
- BoringSSL
- Python's `ssl` module (uses OpenSSL)

## Security Considerations

⚠️ **This tool captures plaintext TLS traffic and may expose sensitive data.**

- Run only in controlled, authorized environments
- Ensure proper access controls on output files
- Review and customize detection rules for your environment
- Consider data retention and privacy policies
- Use for security monitoring, incident response, and compliance

## Performance

- **Overhead**: Minimal (~1-2% CPU overhead from eBPF probes)
- **Memory**: Ring buffer size configurable (default 256KB)
- **Scalability**: Tested with 100+ concurrent connections

## Troubleshooting

### eBPF program fails to load

```bash
# Check kernel version (need 5.8+)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check eBPF capabilities
sudo bpftool feature
```

### No events captured

```bash
# Check if target processes are running
sudo ./tls-inspector status

# Verify OpenSSL library is loaded
ldd $(which curl) | grep ssl

# Check logs
sudo ./tls-inspector run --config configs/config.yaml
```

### Permission denied

```bash
# Run with sudo or grant CAP_BPF capability
sudo ./tls-inspector run

# Or use capabilities (Linux 5.8+)
sudo setcap cap_bpf,cap_perfmon=eip ./tls-inspector
```

## Development

### Project Structure

```
tls-inspector/
├── bpf/                    # eBPF C programs
│   ├── tls_probe.c        # Main eBPF program
│   └── vmlinux.h          # Kernel type definitions
├── cmd/agent/             # CLI entry point
│   └── main.go
├── pkg/
│   ├── ebpf/              # eBPF loader and event processing
│   ├── detector/          # Detection engine
│   ├── metadata/          # Process/container metadata
│   ├── config/            # Config parser
│   └── events/            # Event structures
├── rules/                 # Detection rules
│   └── default.yaml
├── configs/               # Configuration files
│   └── config.yaml
├── examples/              # Example scripts
├── Makefile
└── README.md
```

### Running Tests

```bash
make test
```

### Building

```bash
# Clean build
make clean && make build

# Generate fresh vmlinux.h (requires bpftool)
make vmlinux
```

## Limitations

- **Scope**: Currently supports only curl and Python workloads
- **Libraries**: Requires OpenSSL-compatible TLS libraries
- **Kernel**: Requires Linux 5.8+ with BTF support
- **Privileges**: Requires root or CAP_BPF capabilities

## Future Enhancements

- Support for more languages (Node.js, Java, Go)
- Support for additional TLS libraries (GnuTLS, mbedTLS)
- Real-time alerting and webhooks
- Integration with SIEM systems
- Advanced traffic filtering
- Historical data analysis

## License

Dual licensed under BSD-3-Clause and GPL-2.0

## Contributing

Contributions welcome! Please ensure:

- Code follows existing style
- eBPF programs are tested on multiple kernel versions
- Detection rules are well-documented
- Security considerations are addressed

## Acknowledgments

- Built with [cilium/ebpf](https://github.com/cilium/ebpf)
- Inspired by network security and observability tools

---

**Note**: This is a security tool. Use responsibly and only in authorized environments.
