# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
Simple JWT Bearer Token Test Script

This script demonstrates the complete JWT bearer token flow:
1. Generate a signed JWT Bearer assertion (RFC 7523)
2. Exchange it for an access token using grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
3. Print token details and test API calls
"""

import os
import json
from dotenv import load_dotenv
from ibm_verify.oauth2.auth.client import OAuthClient

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# Configuration
TENANT_URL = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID = os.getenv("IBM_JWT_CLIENT_ID") or os.getenv("IBM_CLIENT_ID")
CLIENT_SECRET = os.getenv("IBM_JWT_CLIENT_SECRET") or os.getenv("IBM_CLIENT_SECRET") or None
PRIVATE_KEY_PATH = os.getenv("IBM_JWT_PRIVATE_KEY_PATH", "certs/private-key.pem")
JWT_SUBJECT = os.getenv("IBM_JWT_SUBJECT") or CLIENT_ID
# kid = certificate label from IBM Verify Security → Certificates (Details page)
JWT_KID = os.getenv("IBM_JWT_KID", "")
# issuer = free-form URL, typically https://<tenant-domain>
JWT_ISSUER = os.getenv("IBM_JWT_ISSUER", TENANT_URL)


def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print('=' * 80)


def main():
    """Main test function."""

    print_section("JWT BEARER TOKEN TEST")

    # Validate configuration
    if not all([TENANT_URL, CLIENT_ID]):
        print("\n❌ Error: Missing configuration in .env file")
        print("Required: IBM_VERIFY_TENANT_URL, IBM_JWT_CLIENT_ID (or IBM_CLIENT_ID)")
        return

    if not JWT_KID:
        print("\n❌ Error: Missing IBM_JWT_KID")
        print("Set IBM_JWT_KID to the certificate label from Security → Certificates in IBM Verify")
        return

    # Resolve private key path relative to this script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    key_path = PRIVATE_KEY_PATH if os.path.isabs(PRIVATE_KEY_PATH) \
        else os.path.join(script_dir, PRIVATE_KEY_PATH)

    if not os.path.exists(key_path):
        print(f"\n❌ Error: Private key not found: {key_path}")
        print("Set IBM_JWT_PRIVATE_KEY_PATH or place key at certs/private-key.pem")
        return

    with open(key_path, "r") as f:
        private_key = f.read()

    print(f"\n✅ Configuration loaded:")
    print(f"   Tenant:  {TENANT_URL}")
    print(f"   Client:  {CLIENT_ID}")
    print(f"   Subject: {JWT_SUBJECT}")
    print(f"   Issuer:  {JWT_ISSUER}")
    print(f"   kid:     {JWT_KID}")
    print(f"   Key:     {key_path}")

    # IBM Verify token endpoint used as JWT audience
    oidc_token_endpoint = f"{TENANT_URL}/oauth2/token"
    print(f"   Audience: {oidc_token_endpoint}")

    # Initialize OAuthClient
    print("\n🔧 Step 1: Initialize OAuth Client")
    client = OAuthClient(base_url=TENANT_URL)

    # Generate JWT Bearer assertion
    print("\n🔐 Step 2: Generate JWT Bearer Assertion")
    print(f"   grant_type: urn:ietf:params:oauth:grant-type:jwt-bearer")
    print(f"   alg: RS256  |  typ: JWT  |  kid: {JWT_KID}")

    try:
        assertion = OAuthClient.generate_jwt_bearer_assertion(
            subject=JWT_SUBJECT,
            token_endpoint=oidc_token_endpoint,
            issuer=JWT_ISSUER,
            private_key=private_key,
            algorithm="RS256",
            key_id=JWT_KID,
        )
        print("   ✅ Assertion generated")
    except Exception as e:
        print(f"   ❌ Error generating assertion: {e}")
        return

    # Exchange assertion for access token
    # ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────
    authorization_details = None
    # Example:
    # authorization_details = [{"type": "openid", "claims": {"id_token": {"acr": {"essential": True}}}}]

    # ── Optional: extra request parameters ────────────────────────────────────
    # Any additional body params your tenant requires (e.g. resource, audience).
    extra_params = None
    # Example:
    # extra_params = {"resource": "https://api.example.com"}

    print("\n🔑 Step 3: Exchange Assertion for Access Token")
    print(f"   POST {oidc_token_endpoint}")
    try:
        token_response = client.jwt_bearer_grant(
            assertion=assertion,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope="openid profile email",
            token_endpoint=oidc_token_endpoint,
            # ── new fields ────────────────────────────────────────────────────
            authorization_details=authorization_details,  # RFC 9396 RAR; None = skip
            extra_params=extra_params,                    # extra body params; None = skip
        )

        access_token = token_response["access_token"]
        print(f"   ✅ Token received!")
        print(f"   Token Type  : {token_response.get('token_type')}")
        print(f"   Expires In  : {token_response.get('expires_in')} seconds")
        print(f"   Scope       : {token_response.get('scope')}")
        if token_response.get("authorization_details"):
            print(f"   AuthZ Details: {token_response['authorization_details']}")

    except Exception as e:
        print(f"   ❌ Error getting token: {e}")
        return

    # Print complete token
    print("\n📋 Step 4: Complete JWT Token")
    print("-" * 80)
    print(access_token)
    print("-" * 80)

    # Decode token
    print("\n🔍 Step 5: Token Claims")
    try:
        import base64
        header_b64, payload_b64, *_ = access_token.split(".")
        padding = "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))

        print(f"   Issuer: {claims.get('iss')}")
        print(f"   Subject: {claims.get('sub')}")
        print(f"   Client ID: {claims.get('client_id')}")
        print(f"   Scope: {claims.get('scope')}")
        print(f"   Expires At: {claims.get('exp')}")

        print("\n   All Claims:")
        print(json.dumps(claims, indent=2))

    except Exception as e:
        print(f"   ⚠️  Could not decode token: {e}")

    # Summary
    print_section("SUMMARY")
    print("\n✅ JWT Bearer Token Flow Complete!")
    print("\n📝 What was tested:")
    print("   • JWT Bearer assertion generation (RFC 7523)")
    print("   • Token exchange via grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer")
    print("   • Token claims extraction")
    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
