# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — OIDC Discovery & JWKS Test Script
==============================================

Demonstrates how to use the OIDC Discovery and JWKS endpoints to:
1. Fetch OpenID Connect configuration (discovery document)
2. Retrieve JSON Web Key Set (JWKS) for token validation
3. Validate JWT tokens using JWKS
4. Explore supported OAuth features

Prerequisites
-------------
- IBM Verify tenant URL
- No authentication required (public endpoints)

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default

Usage
-----
    cd verify-python-sdk
    python sample-scripts/test_discovery_jwks.py
"""

import os
import sys
import json
from typing import Dict, Any

from dotenv import load_dotenv

# ── SDK imports ───────────────────────────────────────────────────────────────
from ibm_verify.auth.client import OAuthClient

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME    = os.getenv("IBM_VERIFY_OP_NAME", "default")


# ── Helpers ───────────────────────────────────────────────────────────────────

def separator(title: str = "") -> None:
    width = 70
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'═' * pad} {title} {'═' * pad}")
    else:
        print("═" * width)


def print_section(title: str) -> None:
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print('─' * 70)


def validate_config() -> None:
    if not TENANT_URL:
        print("❌  Missing required environment variable: IBM_VERIFY_TENANT_URL")
        print("\nCreate a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)
    
    if TENANT_URL and not TENANT_URL.startswith(("http://", "https://")):
        print("❌  IBM_VERIFY_TENANT_URL must start with https:// or http://")
        print(f"    Current value: {TENANT_URL}")
        print(f"    Expected: https://{TENANT_URL}")
        sys.exit(1)


def print_json(data: Dict[str, Any], indent: int = 2) -> None:
    """Pretty print JSON data."""
    print(json.dumps(data, indent=indent))


def print_key_value(key: str, value: Any, indent: int = 4) -> None:
    """Print a key-value pair with indentation."""
    spaces = " " * indent
    if isinstance(value, list):
        print(f"{spaces}{key}:")
        for item in value:
            print(f"{spaces}  • {item}")
    else:
        print(f"{spaces}{key}: {value}")


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    separator("IBM Verify — Discovery & JWKS Test")
    print(f"\n  Tenant URL: {TENANT_URL}")
    print(f"  OP Name   : {OP_NAME}")

    # ── Initialize SDK client ─────────────────────────────────────────────────
    client = OAuthClient(base_url=TENANT_URL)

    # ══════════════════════════════════════════════════════════════════════════
    # PART 1: OIDC Discovery
    # ══════════════════════════════════════════════════════════════════════════

    print_section("PART 1: OIDC Discovery Document")
    
    print("\n  📡 Fetching OIDC discovery document...")
    print(f"     URL: {TENANT_URL}/oauth2/.well-known/openid-configuration")

    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print("\n  ✅ Discovery document loaded successfully!")
    except Exception as exc:
        print(f"\n  ❌ Failed to load discovery: {exc}")
        sys.exit(1)

    # ── Display key endpoints ─────────────────────────────────────────────────
    print("\n  🔗 Key Endpoints:")
    print_key_value("Issuer", metadata.get("issuer"))
    print_key_value("Authorization", metadata.get("authorization_endpoint"))
    print_key_value("Token", metadata.get("token_endpoint"))
    print_key_value("UserInfo", metadata.get("userinfo_endpoint"))
    print_key_value("JWKS URI", metadata.get("jwks_uri"))
    print_key_value("Introspection", metadata.get("introspection_endpoint"))
    print_key_value("Revocation", metadata.get("revocation_endpoint"))
    print_key_value("Device Authorization", metadata.get("device_authorization_endpoint"))
    print_key_value("End Session", metadata.get("end_session_endpoint"))

    # ── Display supported features ────────────────────────────────────────────
    print("\n  🎯 Supported Grant Types:")
    grant_types = metadata.get("grant_types_supported", [])
    if grant_types:
        for grant in grant_types:
            print(f"      ✓ {grant}")
    else:
        print("      (Not specified in discovery)")

    print("\n  🔐 Supported Response Types:")
    response_types = metadata.get("response_types_supported", [])
    if response_types:
        for resp_type in response_types:
            print(f"      ✓ {resp_type}")

    print("\n  📝 Supported Scopes:")
    scopes = metadata.get("scopes_supported", [])
    if scopes:
        for scope in scopes:
            print(f"      ✓ {scope}")

    print("\n  🔑 Supported Token Endpoint Auth Methods:")
    auth_methods = metadata.get("token_endpoint_auth_methods_supported", [])
    if auth_methods:
        for method in auth_methods:
            status = "✅" if method in ["client_secret_post", "client_secret_basic", "private_key_jwt", "tls_client_auth"] else "ℹ️"
            print(f"      {status} {method}")

    print("\n  🔒 Supported Signing Algorithms:")
    algorithms = metadata.get("id_token_signing_alg_values_supported", [])
    if algorithms:
        for alg in algorithms:
            print(f"      ✓ {alg}")

    print("\n  🎨 Supported Claims:")
    claims = metadata.get("claims_supported", [])
    if claims:
        # Show first 10 claims
        for claim in claims[:10]:
            print(f"      ✓ {claim}")
        if len(claims) > 10:
            print(f"      ... and {len(claims) - 10} more")

    # ── Display PKCE support ──────────────────────────────────────────────────
    print("\n  🛡️  PKCE Support:")
    pkce_methods = metadata.get("code_challenge_methods_supported", [])
    if pkce_methods:
        for method in pkce_methods:
            print(f"      ✓ {method}")
    else:
        print("      (Not specified - may still be supported)")

    # ── Optional: Show full discovery document ────────────────────────────────
    print("\n  📄 Full Discovery Document:")
    show_full = input("     Display full JSON? [y/N]: ").strip().lower()
    if show_full == "y":
        print("\n")
        print_json(dict(metadata), indent=2)

    # ══════════════════════════════════════════════════════════════════════════
    # PART 2: JWKS (JSON Web Key Set)
    # ══════════════════════════════════════════════════════════════════════════

    print_section("PART 2: JSON Web Key Set (JWKS)")

    jwks_uri = metadata.get("jwks_uri")
    if not jwks_uri:
        print("\n  ⚠️  No JWKS URI found in discovery document")
        return

    print(f"\n  📡 Fetching JWKS from: {jwks_uri}")

    try:
        jwks = client.get_jwks(op_name=OP_NAME)
        print("\n  ✅ JWKS loaded successfully!")
    except Exception as exc:
        print(f"\n  ❌ Failed to load JWKS: {exc}")
        return

    # ── Display key information ───────────────────────────────────────────────
    keys = jwks.get("keys", [])
    print(f"\n  🔑 Number of keys: {len(keys)}")

    for i, key in enumerate(keys, 1):
        print(f"\n  Key #{i}:")
        print_key_value("Key Type (kty)", key.get("kty"))
        print_key_value("Key ID (kid)", key.get("kid"))
        print_key_value("Algorithm (alg)", key.get("alg"))
        print_key_value("Use", key.get("use"))
        
        if key.get("kty") == "RSA":
            print_key_value("Modulus (n)", f"{key.get('n', '')[:40]}..." if key.get('n') else "N/A")
            print_key_value("Exponent (e)", key.get("e"))
        elif key.get("kty") == "EC":
            print_key_value("Curve", key.get("crv"))
            print_key_value("X Coordinate", f"{key.get('x', '')[:40]}..." if key.get('x') else "N/A")
            print_key_value("Y Coordinate", f"{key.get('y', '')[:40]}..." if key.get('y') else "N/A")

    # ── Optional: Show full JWKS ──────────────────────────────────────────────
    print("\n  📄 Full JWKS:")
    show_full_jwks = input("     Display full JSON? [y/N]: ").strip().lower()
    if show_full_jwks == "y":
        print("\n")
        print_json(jwks, indent=2)

    # ══════════════════════════════════════════════════════════════════════════
    # PART 3: Token Validation Example
    # ══════════════════════════════════════════════════════════════════════════

    print_section("PART 3: JWT Token Validation (Example)")

    print("\n  💡 How to validate JWT tokens using JWKS:")
    print("\n  1. Parse the JWT header to get the 'kid' (Key ID)")
    print("  2. Find the matching key in JWKS using the 'kid'")
    print("  3. Use the public key to verify the JWT signature")
    print("  4. Validate claims (exp, iat, iss, aud, etc.)")

    print("\n  📝 Example code:")
    print("""
    from authlib.jose import jwt, JsonWebKey
    
    # Load JWKS
    jwks = client.get_jwks()
    key_set = JsonWebKey.import_key_set(jwks)
    
    # Verify and decode JWT
    try:
        claims = jwt.decode(
            token,
            key_set,
            claims_options={
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": client_id},
            }
        )
        print("Token is valid!")
        print(f"Subject: {claims['sub']}")
        print(f"Expires: {claims['exp']}")
    except Exception as e:
        print(f"Token validation failed: {e}")
    """)

    # ══════════════════════════════════════════════════════════════════════════
    # PART 4: Caching Recommendations
    # ══════════════════════════════════════════════════════════════════════════

    print_section("PART 4: Best Practices")

    print("\n  ✅ Discovery Document Caching:")
    print("     • Cache for 24 hours (discovery rarely changes)")
    print("     • Refresh on startup or when endpoints fail")
    print("     • Store in memory or persistent cache")

    print("\n  ✅ JWKS Caching:")
    print("     • Cache for 1-24 hours")
    print("     • Refresh when 'kid' not found in cache")
    print("     • Use Cache-Control headers if available")

    print("\n  ✅ Token Validation:")
    print("     • Always validate signature using JWKS")
    print("     • Check expiration (exp claim)")
    print("     • Verify issuer (iss claim)")
    print("     • Verify audience (aud claim)")
    print("     • Check not-before (nbf claim) if present")

    print("\n  ✅ Security:")
    print("     • Always use HTTPS for discovery/JWKS")
    print("     • Validate SSL certificates")
    print("     • Don't trust tokens without signature verification")
    print("     • Implement proper error handling")

    # ══════════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════════

    separator("Summary")
    print("\n  🎉 Discovery & JWKS test completed successfully!")
    print("\n  📊 Results:")
    print(f"     • Discovery endpoint: ✅ Working")
    print(f"     • JWKS endpoint: ✅ Working")
    print(f"     • Number of keys: {len(keys)}")
    print(f"     • Supported grant types: {len(grant_types)}")
    print(f"     • Supported auth methods: {len(auth_methods)}")

    separator()
    print()


if __name__ == "__main__":
    main()
