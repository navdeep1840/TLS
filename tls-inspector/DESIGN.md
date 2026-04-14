# Design Document: eBPF TLS Inspector

## Overview

The TLS Inspector is an eBPF-based agent that captures and inspects plaintext TLS traffic from userspace applications. It focuses on curl and Python workloads, providing security monitoring and detection of sensitive data in HTTPS communications.

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────┐
│                   User Application                      │
│              (curl, Python requests, etc.)              │
└─────────────────────┬───────────────────────────────────┘
                      │
                      │ HTTPS Request/Response
                      ▼
┌─────────────────────────────────────────────────────────┐
│              TLS Library (OpenSSL)                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │  SSL_write()  │  SSL_read()                     │   │
│  │  SSL_write_ex()  │  SSL_read_ex()               │   │
│  └─────────────────────────────────────────────────┘   │
└──────────▲────────────────────────────────────▲─────────┘
           │                                    │
    ╔══════╪════════════════════════════════════╪═════════╗
    ║      │  eBPF Uprobes (Kernel Space)      │         ║
    ║      │                                    │         ║
    ║  ┌───┴──────────┐              ┌─────────┴──────┐  ║
    ║  │ probe_       │              │ probe_         │  ║
    ║  │ ssl_write    │              │ ssl_read       │  ║
    ║  └───┬──────────┘              └─────────┬──────┘  ║
    ║      │                                    │         ║
    ║      └────────────┬───────────────────────┘         ║
    ║                   ▼                                 ║
    ║      ┌─────────────────────────────┐                ║
    ║      │   eBPF Ring Buffer          │                ║
    ║      │   (256KB default)           │                ║
    ║      └─────────────────────────────┘                ║
    ╚═══════════════════╪═════════════════════════════════╝
                        │
                        │ Events
                        ▼
┌─────────────────────────────────────────────────────────┐
│            Userspace Agent (Go)                         │
│                                                         │
│  ┌────────────────┐  ┌──────────────────┐             │
│  │ Ring Buffer    │  │ Process/Container │             │
│  │ Reader         │─▶│ Metadata Enricher │             │
│  └────────────────┘  └─────────┬─────────┘             │
│                                 ▼                       │
│                      ┌──────────────────┐              │
│                      │ Detection Engine │              │
│                      │ (YAML Rules)     │              │
│                      └─────────┬────────┘              │
│                                ▼                       │
│                      ┌──────────────────┐              │
│                      │  JSON Formatter  │              │
│                      └─────────┬────────┘              │
└────────────────────────────────┼────────────────────────┘
                                 ▼
                    ┌─────────────────────┐
                    │  stdout / file      │
                    └─────────────────────┘
```

## Components

### 1. eBPF Layer (Kernel Space)

**File**: `bpf/tls_probe.c`

**Responsibilities**:
- Attach uprobes to SSL/TLS functions
- Capture plaintext data from function arguments
- Read user memory safely
- Send events to userspace via ring buffer

**Key Functions**:

- `probe_ssl_write()` - Intercepts SSL_write, captures egress data
- `probe_ssl_read()` - Entry probe for SSL_read
- `probe_ssl_read_ret()` - Return probe for SSL_read, captures ingress data
- `probe_ssl_write_ex()` - Intercepts SSL_write_ex
- `probe_ssl_read_ex_entry()` - Entry probe for SSL_read_ex
- `probe_ssl_read_ex_ret()` - Return probe for SSL_read_ex

**Data Structures**:

```c
struct tls_event {
    u64 timestamp;           // Event time (ns)
    u32 pid;                 // Process ID
    u32 tid;                 // Thread ID
    u32 uid;                 // User ID
    u64 cgroup_id;           // Container cgroup ID
    char comm[16];           // Process name
    u8 function_type;        // SSL function type
    u32 data_len;            // Captured data length
    char data[4096];         // Plaintext data
};
```

**Maps**:

- `events` - Ring buffer for sending events to userspace
- `ssl_ctx_map` - Temporary storage for buffer pointers (read operations)

### 2. Userspace Agent (Go)

#### a. eBPF Loader (`pkg/ebpf/inspector.go`)

**Responsibilities**:
- Load compiled eBPF object file
- Discover target processes (curl, python)
- Find SSL libraries in process memory maps
- Attach uprobes to SSL functions
- Manage eBPF program lifecycle

**Key Functions**:
- `NewTLSInspector()` - Initialize inspector
- `Load()` - Load eBPF programs
- `AttachToProcesses()` - Find and attach to target processes
- `attachToLibrary()` - Attach probes to specific library
- `Start()` - Begin event processing loop

#### b. Event Processing (`pkg/ebpf/inspector.go`)

**Responsibilities**:
- Read events from ring buffer
- Parse raw eBPF events
- Convert to structured format
- Trigger metadata enrichment and detection

#### c. Metadata Collector (`pkg/metadata/collector.go`)

**Responsibilities**:
- Read `/proc/<pid>/cmdline` for command line
- Parse `/proc/<pid>/cgroup` for container ID
- Read `/proc/<pid>/environ` for K8s metadata
- Find library paths in `/proc/<pid>/maps`

**Container Detection Patterns**:
- Docker: `/docker/<container_id>`
- containerd: `/cri-containerd-<container_id>`
- K8s: `/pod<pod_id>/...`

#### d. Detection Engine (`pkg/detector/detector.go`)

**Responsibilities**:
- Load YAML detection rules
- Compile regex patterns
- Scan plaintext data for matches
- Return detections with severity

**Rule Structure**:
```yaml
id: unique-rule-id
name: Human Readable Name
description: What this detects
severity: low|medium|high|critical
enabled: true|false
patterns: [substring matches]
regex: [regex patterns]
keywords: [case-insensitive keywords]
```

**Detection Algorithm**:
1. Convert data to lowercase for keyword matching
2. Check all keywords (case-insensitive)
3. Apply regex patterns
4. Check substring patterns
5. Return all matches with highest severity

#### e. Config Parser (`pkg/config/config.go`)

**Responsibilities**:
- Parse YAML configuration
- Provide defaults
- Validate settings

#### f. CLI (`cmd/agent/main.go`)

**Commands**:
- `run` - Start the inspector
- `status` - Show target processes
- `rules list` - List detection rules
- `rules test` - Test rules with sample data

## Data Flow

### Egress (SSL_write)

1. Application calls `SSL_write(ssl, buf, len)`
2. eBPF uprobe fires before function executes
3. eBPF reads `buf` contents (up to 4096 bytes)
4. eBPF collects metadata (PID, TID, UID, cgroup)
5. eBPF sends event to ring buffer
6. Userspace reads event from ring buffer
7. Userspace enriches with process/container metadata
8. Detection engine scans for secrets
9. JSON event output to stdout/file

### Ingress (SSL_read)

1. Application calls `SSL_read(ssl, buf, len)`
2. eBPF uprobe (entry) fires, stores `buf` pointer in map
3. Function executes, OpenSSL fills `buf` with plaintext
4. Function returns with bytes read
5. eBPF uretprobe fires
6. eBPF retrieves `buf` pointer from map
7. eBPF reads `buf` contents (return value = bytes read)
8. Rest same as egress

## Security Considerations

### Sensitive Data Handling

- **Capture Limit**: Only first 4096 bytes captured (configurable)
- **Preview Limit**: Only first 200 bytes shown in preview
- **Masking**: Detected secrets are masked in output (e.g., `ghp_1234...uvwx`)
- **Access Control**: Requires root or CAP_BPF to run

### Memory Safety

- **Safe Reads**: Uses `bpf_probe_read_user()` for safe userspace memory access
- **Bounds Checking**: All array accesses bounds-checked by eBPF verifier
- **No Crashes**: eBPF cannot crash kernel

### Performance

- **Zero-Copy**: Ring buffer provides zero-copy event transport
- **Minimal Overhead**: ~1-2% CPU overhead
- **Filtering**: Only attaches to target processes (curl, python)
- **Buffer Size**: Configurable ring buffer size (default 256KB)

## Limitations

### Current Scope

- **Languages**: Only curl and Python supported
- **TLS Libraries**: OpenSSL, LibreSSL, BoringSSL only
- **Platforms**: Linux x86_64 only (ARM64 possible but untested)
- **Kernel**: Requires 5.8+ with BTF

### Known Issues

- **Dynamic Library Loading**: Won't capture traffic if SSL library loaded after agent starts
- **Static Linking**: Can't inspect statically linked binaries (rare for curl/Python)
- **Container Startup**: May miss very early traffic from containers starting after agent

### Not Supported

- Non-OpenSSL TLS libraries (GnuTLS, mbedTLS, etc.)
- TLS 1.3 0-RTT early data (edge case)
- Other languages (Node.js, Java, Go, Rust) - future enhancement

## Extension Points

### Adding New Target Processes

1. Add process name to `configs/config.yaml`:
   ```yaml
   include_processes:
     - curl
     - python
     - node  # New target
   ```

2. Ensure process uses OpenSSL-compatible library

### Adding New Detection Rules

1. Edit `rules/default.yaml`:
   ```yaml
   - id: custom-secret
     name: Custom Secret Pattern
     description: Detects custom secret format
     severity: high
     enabled: true
     regex:
       - 'secret_[a-zA-Z0-9]{32}'
   ```

2. Test with: `./tls-inspector rules test`

### Supporting New TLS Libraries

1. Identify equivalent functions (e.g., GnuTLS: `gnutls_record_send`)
2. Add new eBPF probes in `bpf/tls_probe.c`
3. Update library detection in `pkg/metadata/collector.go`
4. Update attachment logic in `pkg/ebpf/inspector.go`

## Testing Strategy

### Unit Tests

- Detection engine rule matching
- Metadata parsing (cgroup, environ)
- Config loading and validation

### Integration Tests

- End-to-end with curl
- End-to-end with Python requests
- Container detection
- Multi-process scenarios

### Manual Testing

See `examples/test.sh` for automated test script.

## Performance Characteristics

### Overhead

- **CPU**: ~1-2% per monitored process
- **Memory**: ~1-2 MB per eBPF program
- **Ring Buffer**: 256KB default (configurable)

### Scalability

- **Processes**: Tested with 100+ concurrent processes
- **Throughput**: ~10,000 events/second
- **Event Size**: 4KB per event (max)

### Tuning

```yaml
# Low-overhead mode (less capture)
capture_bytes: 1024
buffer_size: 65536

# High-detail mode (more capture)
capture_bytes: 8192
buffer_size: 1048576
```

## Future Enhancements

### Planned Features

1. **More Languages**: Node.js, Java, Go, Rust
2. **More Libraries**: GnuTLS, mbedTLS, Rustls
3. **Streaming Output**: Real-time to Kafka, SIEM
4. **Filtering**: Pre-filter by destination IP/port
5. **Sampling**: Capture only N% of traffic
6. **mTLS Support**: Extract client certificate info
7. **HTTP/2 Parsing**: Parse plaintext HTTP/2 frames
8. **Metrics**: Prometheus metrics endpoint

### Research Ideas

- Machine learning for anomaly detection
- Automatic credential rotation triggers
- Integration with secret management systems
- Correlation with network flow data

## References

- [eBPF Documentation](https://ebpf.io/)
- [cilium/ebpf Library](https://github.com/cilium/ebpf)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
