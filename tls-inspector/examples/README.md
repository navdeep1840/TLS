# TLS Inspector Examples

This directory contains example scripts demonstrating TLS inspection for curl and Python applications.

## Examples

### Python Scripts

1. **python_requests.py** - Using the popular `requests` library
   ```bash
   python3 python_requests.py
   ```

2. **python_urllib3.py** - Using `urllib3` library
   ```bash
   python3 python_urllib3.py
   ```

3. **python_httpx.py** - Using `httpx` async HTTP client
   ```bash
   pip install httpx
   python3 python_httpx.py
   ```

### Curl Scripts

1. **curl_examples.sh** - Various curl commands with different authentication methods
   ```bash
   bash curl_examples.sh
   ```

### Test Script

**test.sh** - Automated test that starts the inspector, generates traffic, and verifies capture
```bash
sudo bash test.sh
```

## Running Examples

### Terminal 1: Start Inspector

```bash
cd /path/to/tls-inspector
sudo ./tls-inspector run
```

### Terminal 2: Run Examples

```bash
# Python examples
python3 examples/python_requests.py

# Curl examples  
bash examples/curl_examples.sh
```

## What to Expect

The inspector will output JSON events showing:

- Plaintext HTTP requests/responses before TLS encryption
- Detected secrets (API keys, tokens, passwords)
- Process and container metadata
- Function calls (SSL_write, SSL_read)

Example output:

```json
{
  "timestamp": "2026-04-14T12:00:00Z",
  "process": "python3",
  "pid": 12345,
  "function": "SSL_write",
  "direction": "egress",
  "plaintext_preview": "GET /get HTTP/1.1...",
  "detections": ["AWS Access Key"],
  "severity": "critical"
}
```
