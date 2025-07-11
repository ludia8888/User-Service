#!/usr/bin/env python3
"""Test key loading"""

import os
import base64

print("Environment variables:")
print(f"JWT_PRIVATE_KEY_BASE64: {'Set' if os.environ.get('JWT_PRIVATE_KEY_BASE64') else 'Not set'}")
print(f"JWT_PUBLIC_KEY_BASE64: {'Set' if os.environ.get('JWT_PUBLIC_KEY_BASE64') else 'Not set'}")

if os.environ.get('JWT_PRIVATE_KEY_BASE64'):
    try:
        private_key_pem = base64.b64decode(os.environ.get('JWT_PRIVATE_KEY_BASE64'))
        print(f"\nDecoded private key length: {len(private_key_pem)} bytes")
        print(f"Private key starts with: {private_key_pem[:30]}")
    except Exception as e:
        print(f"Error decoding private key: {e}")

if os.environ.get('JWT_PUBLIC_KEY_BASE64'):
    try:
        public_key_pem = base64.b64decode(os.environ.get('JWT_PUBLIC_KEY_BASE64'))
        print(f"\nDecoded public key length: {len(public_key_pem)} bytes")
        print(f"Public key starts with: {public_key_pem[:30]}")
    except Exception as e:
        print(f"Error decoding public key: {e}")

# Try to import and use jwks_service
import sys
sys.path.insert(0, 'src')

try:
    from services.jwks_service import jwks_service
    print("\n✅ JWKS service loaded successfully")
    print(f"Key ID: {jwks_service.get_kid()}")
except Exception as e:
    print(f"\n❌ Failed to load JWKS service: {e}")
    import traceback
    traceback.print_exc()