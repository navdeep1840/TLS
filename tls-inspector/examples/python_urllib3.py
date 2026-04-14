#!/usr/bin/env python3
"""
Example using urllib3 library.
"""

import urllib3
import json

http = urllib3.PoolManager()

def test_urllib3():
    print("Testing urllib3 HTTPS request...")
    
    # Basic request
    response = http.request('GET', 'https://httpbin.org/get')
    print(f"Status: {response.status}")
    
    # Request with headers containing secrets
    headers = {
        'X-API-Key': 'AKIAIOSFODNN7EXAMPLE',
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
    }
    response = http.request('GET', 'https://httpbin.org/headers', headers=headers)
    print(f"Status with auth: {response.status}")

if __name__ == '__main__':
    test_urllib3()
