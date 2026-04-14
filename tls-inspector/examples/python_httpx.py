#!/usr/bin/env python3
"""
Example using httpx library (async HTTP client).
"""

import httpx

def test_httpx():
    print("Testing httpx HTTPS request...")
    
    with httpx.Client() as client:
        # Basic request
        response = client.get('https://httpbin.org/get')
        print(f"Status: {response.status_code}")
        
        # Request with sensitive data
        headers = {
            'X-Secret-Key': 'sk_live_abcdefghijklmnopqrstuvwxyz',
            'X-GitHub-Token': 'ghp_' + 'x' * 36
        }
        response = client.get('https://httpbin.org/headers', headers=headers)
        print(f"Status with secrets: {response.status_code}")

if __name__ == '__main__':
    try:
        test_httpx()
    except ImportError:
        print("httpx not installed. Install with: pip install httpx")
