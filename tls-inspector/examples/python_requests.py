#!/usr/bin/env python3
"""
Example Python script using requests library.
This demonstrates TLS inspection of Python HTTPS traffic.
"""

import requests
import json

def test_basic_request():
    """Basic HTTPS request"""
    print("Testing basic HTTPS request...")
    response = requests.get('https://api.github.com')
    print(f"Status: {response.status_code}")
    print(f"Headers: {dict(list(response.headers.items())[:3])}")

def test_with_auth_header():
    """Request with Authorization header (will trigger detection)"""
    print("\nTesting request with auth token...")
    headers = {
        'Authorization': 'Bearer ghp_1234567890abcdefghijklmnopqrstuv'
    }
    try:
        response = requests.get('https://api.github.com/user', headers=headers)
        print(f"Status: {response.status_code}")
    except Exception as e:
        print(f"Request failed (expected): {e}")

def test_with_api_key():
    """Request with API key in URL params"""
    print("\nTesting request with API key...")
    params = {
        'api_key': 'sk-1234567890abcdefghijklmnop',
        'format': 'json'
    }
    try:
        response = requests.get('https://httpbin.org/get', params=params)
        print(f"Status: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def test_post_with_credentials():
    """POST request with credentials in body"""
    print("\nTesting POST with credentials...")
    data = {
        'username': 'testuser',
        'password': 'MySecretPassword123',
        'api_token': 'xoxb-1234567890-abcdefghijklmnop'
    }
    try:
        response = requests.post('https://httpbin.org/post', json=data)
        print(f"Status: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("="*50)
    print("TLS Inspector - Python Requests Example")
    print("="*50)
    
    test_basic_request()
    test_with_auth_header()
    test_with_api_key()
    test_post_with_credentials()
    
    print("\n" + "="*50)
    print("Done! Check TLS inspector output for events.")
    print("="*50)
