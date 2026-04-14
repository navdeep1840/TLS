#!/bin/bash

# Example curl commands that will trigger TLS inspection

echo "=============================================="
echo "TLS Inspector - Curl Examples"
echo "==============================================\n"

echo "1. Basic HTTPS request:"
curl -s https://api.github.com | head -n 5
echo ""

echo "\n2. Request with Authorization header (JWT):"
curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" \
  https://httpbin.org/headers | head -n 10
echo ""

echo "\n3. Request with API key:"
curl -s -H "X-API-Key: AKIAIOSFODNN7EXAMPLE" \
  https://httpbin.org/headers | head -n 10
echo ""

echo "\n4. POST with credentials:"
curl -s -X POST https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecretPass123","api_key":"sk-test123456789"}' \
  | head -n 15
echo ""

echo "\n5. Request with GitHub token:"
curl -s -H "Authorization: token ghp_1234567890abcdefghijklmnopqrstuv" \
  https://api.github.com/user | head -n 5
echo ""

echo "\n=============================================="
echo "Done! Check TLS inspector output for events."
echo "==============================================\n"
