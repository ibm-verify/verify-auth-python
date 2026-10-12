# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Refresh Token Flow (RFC 6749 Section 6)
====================================================

Demonstrates the Refresh Token grant flow using the IBM Verify Python SDK.
This flow allows applications to obtain new access tokens without requiring
the user to re-authenticate, enabling long-lived sessions.

Flow steps
----------
1. Obtain initial tokens using Password Grant (or any other grant type)
2. Wait for access token to expire (or simulate expiration)
3. Use the refresh token to obtain a new access token
4. (Optional) Introspect both old and new tokens to verify the refresh

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin
2. Navigate to Applications → Applications → Add application → Custom Application → OIDC
3. Fill in:
     General tab:
       Application name : Refresh Token Test App
       Application URL  : http://localhost
       Company name     : <your org>
     Sign-on tab:
       Grant types      : ✅ Resource owner password credentials
                          ✅ Refresh token
       Client auth      : Client secret (post) or Client secret (basic)
       Scopes           : openid profile email
     Entitlements tab:
       ✅ Add the user(s) who will test this application
4. Save → copy the Client ID and Client Secret into .env

Common Errors
-------------
• "invalid_grant" → Refresh token expired, revoked, or invalid
• "invalid_client" → Wrong client credentials
• "invalid_scope" → Requested scope exceeds original grant

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_USER_CLIENT_ID=your-client-id
    IBM_USER_CLIENT_SECRET=your-client-secret
    IBM_USERNAME=your-username
    IBM_PASSWORD=your-password

Usage
-----
    cd verify-auth-python
    python sample-scripts/test_refresh_token_flow.py
"""

import os
import sys
import json
import time
from typing import Dict, Any

from dotenv import load_dotenv

# ── SDK imports ───────────────────────────────────────────────────────────────
from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID     = os.getenv("IBM_USER_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_USER_CLIENT_SECRET", "")
USERNAME      = os.getenv("IBM_USERNAME", "")
PASSWORD      = os.getenv("IBM_PASSWORD", "")
AUTHZ_HEADER  = os.getenv("IBM_AUTHZ_HEADER", "")

# ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────────
# Sent in both the initial password grant and the refresh token request.
# Set to None to make plain requests.
AUTHORIZATION_DETAILS = None
# Example:
# AUTHORIZATION_DETAILS = [{"type": "account_information", "access": {"balances": ["read"]}}]

# ── Optional: extra request parameters ────────────────────────────────────────
# Merged into the token request body for both grant calls.
# Set to None if not needed.
EXTRA_PARAMS = None
# Example:
# EXTRA_PARAMS = {"resource": "https://api.example.com"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def separator(title: str = "") -> None:
    width = 70
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print("─" * width)


def validate_config() -> None:
    missing = []
    if not TENANT_URL:
        missing.append("IBM_VERIFY_TENANT_URL")
    if not CLIENT_ID:
        missing.append("IBM_USER_CLIENT_ID")
    if not CLIENT_SECRET:
        missing.append("IBM_USER_CLIENT_SECRET")
    if not USERNAME:
        missing.append("IBM_USERNAME")
    if not PASSWORD:
        missing.append("IBM_PASSWORD")
    
    if missing:
        print("❌  Missing required environment variables:")
        for var in missing:
            print(f"    • {var}")
        print("\nCreate a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)
    
    # Validate that TENANT_URL has a protocol
    if TENANT_URL and not TENANT_URL.startswith(("http://", "https://")):
        print("❌  IBM_VERIFY_TENANT_URL must start with https:// or http://")
        print(f"    Current value: {TENANT_URL}")
        print(f"    Expected: https://{TENANT_URL}")
        sys.exit(1)


def display_token_info(token: Dict[str, Any], label: str = "Token") -> None:
    """Display token information in a formatted way."""
    print(f"\n  ✅ {label} received!")
    print(f"     token_type    : {token.get('token_type', 'N/A')}")
    print(f"     expires_in    : {token.get('expires_in', 'N/A')} seconds")
    print(f"     scope         : {token.get('scope', 'N/A')}")
    
    access_token = str(token.get('access_token', ''))
    if access_token:
        print(f"     access_token  : {access_token[:60]}...")
    
    if token.get("id_token"):
        id_token = str(token.get('id_token', ''))
        print(f"     id_token      : {id_token[:60]}...")
    
    if token.get("refresh_token"):
        refresh_token = str(token.get('refresh_token', ''))
        print(f"     refresh_token : {refresh_token[:60]}...")


def introspect_and_display(
    client: OAuthClient,
    token: str,
    label: str = "Token"
) -> Dict[str, Any]:
    """Introspect a token and display its status."""
    try:
        result = client.introspect_token(
            token=token,
            op_name=OP_NAME,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            token_type_hint="access_token",
        )
        
        if result.get("active"):
            print(f"\n  ✅ {label} is ACTIVE")
            print(f"     Subject   : {result.get('sub', 'N/A')}")
            print(f"     Username  : {result.get('username', 'N/A')}")
            print(f"     Scope     : {result.get('scope', 'N/A')}")
            print(f"     Client ID : {result.get('client_id', 'N/A')}")
            
            if result.get('exp'):
                from datetime import datetime
                exp = datetime.fromtimestamp(result['exp'])
                print(f"     Expires   : {exp}")
        else:
            print(f"\n  ⚠️  {label} is NOT ACTIVE (expired or revoked)")
        
        return result
    except Exception as exc:
        print(f"\n  ⚠️  Introspection failed: {exc}")
        return {}


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    print("\n" + "=" * 70)
    print("  IBM Verify — Refresh Token Flow Demonstration")
    print("=" * 70)

    # ── Initialize SDK client ─────────────────────────────────────────────────
    client = OAuthClient(base_url=TENANT_URL)

    # Load OIDC discovery
    separator("STEP 0 — Load OIDC Discovery")
    print(f"  Tenant  : {TENANT_URL}")
    print(f"  OP name : {OP_NAME}")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print(f"  ✅ Discovery loaded")
        print(f"     Token endpoint : {metadata.get('token_endpoint')}")
    except Exception as exc:
        print(f"  ⚠️  Discovery failed ({exc}) — falling back to default paths")

    # ── Step 1 — Obtain initial tokens ────────────────────────────────────────
    separator("STEP 1 — Obtain Initial Tokens (Password Grant)")
    print(f"  client_id : {CLIENT_ID}")
    print(f"  username  : {USERNAME}")
    print(f"  Requesting tokens with refresh_token grant enabled...")

    try:
        initial_token = client.password_grant(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            # ── new fields ────────────────────────────────────────────────────
            authorization_details=AUTHORIZATION_DETAILS,  # RFC 9396 RAR; None = skip
            extra_params=EXTRA_PARAMS,                    # extra body params; None = skip
        )
    except VerifyError as exc:
        print(f"\n  ❌ Password grant failed: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     1. Verify username and password are correct")
        print("     2. Check that the user is entitled to the application")
        print("     3. Ensure 'Resource owner password credentials' grant is enabled")
        print("     4. Ensure 'Refresh token' grant is enabled in IBM Verify")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    display_token_info(initial_token, "Initial tokens")

    # Check if refresh token is present
    if not initial_token.get("refresh_token"):
        print("\n  ❌ No refresh_token in response!")
        print("\n  💡 Troubleshooting:")
        print("     1. Ensure 'Refresh token' grant type is enabled in IBM Verify")
        print("     2. Check application configuration in IBM Verify admin console")
        print("     3. Navigate to: Applications → Your App → Sign-on tab")
        print("     4. Grant types should include: ✅ Refresh token")
        sys.exit(1)

    # ── Step 2 — Introspect initial access token ──────────────────────────────
    separator("STEP 2 — Introspect Initial Access Token")
    print("  Verifying the initial access token is active...")
    introspect_and_display(
        client,
        initial_token["access_token"],
        "Initial access token"
    )

    # ── Step 3 — Wait or simulate token expiration ────────────────────────────
    separator("STEP 3 — Simulate Token Expiration")
    expires_in = initial_token.get("expires_in", 3600)
    print(f"  Access token expires in: {expires_in} seconds")
    print("\n  Options:")
    print("    1. Wait for token to expire naturally (not recommended)")
    print("    2. Continue immediately to test refresh flow")
    
    choice = input("\n  Continue with refresh? [Y/n]: ").strip().lower()
    if choice == "n":
        print(f"\n  Waiting {expires_in} seconds for token to expire...")
        time.sleep(expires_in + 5)
        print("  ✅ Token should now be expired")

    # ── Step 4 — Refresh the access token ─────────────────────────────────────
    separator("STEP 4 — Refresh Access Token")
    print(f"  client_id     : {CLIENT_ID}")
    print(f"  refresh_token : {str(initial_token['refresh_token'])[:40]}...")
    print("\n  Requesting new access token using refresh token...")

    try:
        refreshed_token = client.refresh_access_token(
            client_id=CLIENT_ID,
            refresh_token=initial_token["refresh_token"],
            client_secret=CLIENT_SECRET,
            # ── new fields ────────────────────────────────────────────────────
            authorization_details=AUTHORIZATION_DETAILS,  # RFC 9396 RAR; None = skip
            extra_params=EXTRA_PARAMS,                    # extra body params; None = skip
        )
    except VerifyError as exc:
        print(f"\n  ❌ Token refresh failed: {exc}")
        print("\n  💡 Common causes:")
        print("     • Refresh token expired (check token lifetime in IBM Verify)")
        print("     • Refresh token was revoked")
        print("     • Client credentials are incorrect")
        print("     • Refresh token grant not enabled")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    display_token_info(refreshed_token, "Refreshed tokens")

    # ── Step 5 — Compare tokens ───────────────────────────────────────────────
    separator("STEP 5 — Compare Old vs New Tokens")
    
    old_access = initial_token.get("access_token", "")
    new_access = refreshed_token.get("access_token", "")
    
    if old_access == new_access:
        print("  ⚠️  Access tokens are IDENTICAL (unusual but possible)")
    else:
        print("  ✅ Access tokens are DIFFERENT (expected)")
        print(f"     Old: {old_access[:40]}...")
        print(f"     New: {new_access[:40]}...")
    
    old_refresh = initial_token.get("refresh_token", "")
    new_refresh = refreshed_token.get("refresh_token", "")
    
    if old_refresh == new_refresh:
        print("\n  ℹ️  Refresh tokens are IDENTICAL (token rotation not enabled)")
    else:
        print("\n  ✅ Refresh tokens are DIFFERENT (token rotation enabled)")
        print(f"     Old: {old_refresh[:40]}...")
        print(f"     New: {new_refresh[:40]}...")

    # ── Step 6 — Introspect both tokens ───────────────────────────────────────
    separator("STEP 6 — Introspect Both Tokens")
    
    print("\n  📋 Old access token:")
    old_result = introspect_and_display(
        client,
        old_access,
        "Old access token"
    )
    
    print("\n  📋 New access token:")
    new_result = introspect_and_display(
        client,
        new_access,
        "New access token"
    )

    # ── Step 7 — Test refresh token reuse (optional) ──────────────────────────
    separator("STEP 7 — Test Refresh Token Reuse (Optional)")
    test_reuse = input("  Test using the same refresh token again? [y/N]: ").strip().lower()
    
    if test_reuse == "y":
        print("\n  Attempting to reuse the original refresh token...")
        try:
            reused_token = client.refresh_access_token(
                client_id=CLIENT_ID,
                refresh_token=old_refresh,
                client_secret=CLIENT_SECRET,
                authorization_details=AUTHORIZATION_DETAILS,
                extra_params=EXTRA_PARAMS,
            )
            print("\n  ⚠️  Refresh token reuse SUCCEEDED")
            print("     This means token rotation is NOT enabled")
            display_token_info(reused_token, "Reused refresh token result")
        except Exception as exc:
            print(f"\n  ✅ Refresh token reuse FAILED (expected with rotation)")
            print(f"     Error: {exc}")
            print("     This means token rotation IS enabled (more secure)")

    # ── Summary ───────────────────────────────────────────────────────────────
    separator("Summary")
    print("\n  🎉 Refresh Token flow completed successfully!")
    print("\n  Key Observations:")
    print(f"     • Initial access token : {old_access[:40]}...")
    print(f"     • Refreshed access token: {new_access[:40]}...")
    print(f"     • Tokens are different  : {'Yes ✅' if old_access != new_access else 'No ⚠️'}")
    print(f"     • Token rotation enabled: {'Yes ✅' if old_refresh != new_refresh else 'No ℹ️'}")
    
    if new_result.get("active"):
        print(f"\n  ✅ New access token is valid and ready to use!")
    
    separator()
    print()


if __name__ == "__main__":
    main()
