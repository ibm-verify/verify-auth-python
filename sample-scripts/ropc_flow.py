# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Resource Owner Password Credentials (ROPC) Flow (RFC 6749 §4.3)
=============================================================================

Demonstrates the Password grant (ROPC) using the IBM Verify Python SDK.
The user's username and password are submitted directly to the token endpoint
and exchanged for an access token — no browser redirect is involved.

⚠️  ROPC is considered a legacy grant type.  It is suitable for trusted
internal tooling, CLI scripts, and migration scenarios.  For new
user-facing applications prefer Authorization Code + PKCE (pkce_flow.py)
or Device Code (device_code_flow.py).

Flow steps
----------
  Step 0 — OIDC discovery
  Step 1 — Password grant → access_token + (optional) refresh_token + id_token
  Step 2 — Introspect the access token
  Step 3 — (Optional) Refresh the access token if a refresh_token was issued

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin
2. Navigate to Applications → Applications → Add application → Custom Application → OIDC
3. Fill in:
     General tab:
       Application name : ROPC App
       Application URL  : http://localhost        ← required field (any URL)
       Company name     : <your org>
     Sign-on tab:
       Grant types      : ✅ Resource owner password credentials
                          ✅ Refresh token  (optional — needed for Step 3)
       Client auth      : Client secret (post)  OR  Client secret (basic)
       Scopes           : openid profile email
     Entitlements tab:
       ✅ Add the user(s) who will test this application
4. Save → copy Client ID and Client Secret into .env

Common errors
-------------
• 400 invalid_grant      → Wrong username or password, or user not entitled
• 401 invalid_client     → Wrong client_id or client_secret
• 400 unauthorized_client → Grant type "password" not enabled on this client
• 403 access_denied      → User locked or tenant policy blocks ROPC

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_USER_CLIENT_ID=your-client-id
    IBM_USER_CLIENT_SECRET=your-client-secret
    IBM_USERNAME=your-username
    IBM_PASSWORD=your-password
    IBM_AUTHZ_HEADER=Bearer <admin-token>    # forwarded as Authorization header

Usage
-----
    cd verify-auth-python
    python sample-scripts/ropc_flow.py
"""

import os
import sys
import json

from dotenv import load_dotenv

from ibm_verify.auth.client import OAuthClient
from ibm_verify.core.errors import VerifyError

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
SCOPE         = "openid profile email"

# ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────────
# Sent in both the password grant and the refresh token request.
# The SDK JSON-encodes this automatically if you pass a list/dict.
# Set to None to make plain requests.
AUTHORIZATION_DETAILS = None
# Example:
# AUTHORIZATION_DETAILS = [
#     {"type": "account_information", "access": {"balances": ["read"]}},
# ]

# ── Optional: extra body parameters ───────────────────────────────────────────
# Merged verbatim into the token request body for both grant calls.
EXTRA_PARAMS = None
# Example:
# EXTRA_PARAMS = {"resource": "https://api.example.com"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def separator(title: str = "") -> None:
    width = 66
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print("─" * width)


def validate_config() -> None:
    missing = [k for k, v in {
        "IBM_VERIFY_TENANT_URL":  TENANT_URL,
        "IBM_USER_CLIENT_ID":     CLIENT_ID,
        "IBM_USER_CLIENT_SECRET": CLIENT_SECRET,
        "IBM_USERNAME":           USERNAME,
        "IBM_PASSWORD":           PASSWORD,
    }.items() if not v]
    if missing:
        print("❌  Missing required environment variables:")
        for var in missing:
            print(f"    • {var}")
        print("\nCreate a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)
    if not TENANT_URL.startswith(("http://", "https://")):
        print("❌  IBM_VERIFY_TENANT_URL must start with https://")
        sys.exit(1)


def display_token(token: dict, label: str) -> None:
    print(f"\n  ✅ {label}")
    print(f"     token_type    : {token.get('token_type')}")
    print(f"     expires_in    : {token.get('expires_in')} s")
    print(f"     scope         : {token.get('scope')}")
    print(f"     access_token  : {str(token.get('access_token', ''))[:60]}...")
    if token.get("id_token"):
        print(f"     id_token      : {str(token['id_token'])[:60]}...")
    if token.get("refresh_token"):
        print(f"     refresh_token : {str(token['refresh_token'])[:60]}...")
    if token.get("authorization_details"):
        print(f"     authz_details : {token['authorization_details']}")


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    print("\n" + "=" * 66)
    print("  IBM Verify — ROPC / Password Grant Flow (RFC 6749 §4.3)")
    print("=" * 66)

    client = OAuthClient(base_url=TENANT_URL)

    # ── Step 0 — OIDC Discovery ───────────────────────────────────────────────
    separator("STEP 0 — OIDC Discovery")
    print(f"  Tenant  : {TENANT_URL}")
    print(f"  OP name : {OP_NAME}")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print(f"  ✅ Discovery loaded")
        print(f"     Token endpoint : {metadata.get('token_endpoint')}")
    except Exception as exc:
        print(f"  ⚠️  Discovery failed ({exc}) — using default paths")

    # ── Step 1 — Password Grant ───────────────────────────────────────────────
    separator("STEP 1 — Password Grant (ROPC)")
    print(f"  client_id  : {CLIENT_ID}")
    print(f"  username   : {USERNAME}")
    print(f"  scope      : {SCOPE}")
    if AUTHORIZATION_DETAILS:
        print(f"  authz_details : {json.dumps(AUTHORIZATION_DETAILS)}")
    if EXTRA_PARAMS:
        print(f"  extra_params  : {EXTRA_PARAMS}")

    try:
        token = client.password_grant(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            scope=SCOPE,
            authorization_details=AUTHORIZATION_DETAILS,
            extra_params=EXTRA_PARAMS,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Password grant failed (HTTP {exc.status_code}): {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 400 invalid_grant      → Wrong username or password, or user not entitled")
        print("     • 401 invalid_client     → Wrong IBM_USER_CLIENT_ID or IBM_USER_CLIENT_SECRET")
        print("     • 400 unauthorized_client → 'password' grant not enabled on this client")
        print("     • 403 access_denied      → User locked or tenant blocks ROPC")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    display_token(token, "Tokens received")

    # ── Step 2 — Introspect ───────────────────────────────────────────────────
    separator("STEP 2 — Token Introspection")
    do_introspect = input("  Introspect the access token? [Y/n]: ").strip().lower()
    if do_introspect != "n":
        try:
            introspection = client.introspect_token(
                token=token["access_token"],
                op_name=OP_NAME,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                token_type_hint="access_token",
            )
            print("\n  Introspection response:")
            print(json.dumps(introspection, indent=4))
            if introspection.get("active"):
                print(f"\n  ✅ Token is ACTIVE")
                print(f"     sub      : {introspection.get('sub', 'n/a')}")
                print(f"     username : {introspection.get('username', 'n/a')}")
                print(f"     scope    : {introspection.get('scope', 'n/a')}")
                if introspection.get("exp"):
                    from datetime import datetime
                    print(f"     expires  : {datetime.fromtimestamp(introspection['exp'])}")
            else:
                print("\n  ⚠️  Token is NOT active")
        except Exception as exc:
            print(f"  ⚠️  Introspection failed: {exc}")

    # ── Step 3 — Refresh (if issued) ─────────────────────────────────────────
    separator("STEP 3 — Refresh Token (optional)")
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        print("  ℹ️  No refresh_token in response — skipping.")
        print("     Enable 'Refresh token' grant on this client to get one.")
    else:
        do_refresh = input("  Refresh the access token now? [Y/n]: ").strip().lower()
        if do_refresh != "n":
            try:
                refreshed = client.refresh_access_token(
                    client_id=CLIENT_ID,
                    refresh_token=refresh_token,
                    client_secret=CLIENT_SECRET,
                    authorization_details=AUTHORIZATION_DETAILS,
                    extra_params=EXTRA_PARAMS,
                )
                display_token(refreshed, "Refreshed tokens")
                old_at = str(token.get("access_token", ""))
                new_at = str(refreshed.get("access_token", ""))
                if old_at != new_at:
                    print(f"\n  ✅ New access token is different from the original (expected)")
                else:
                    print(f"\n  ⚠️  Tokens are identical (check token lifetime settings)")
            except VerifyError as exc:
                print(f"\n  ❌ Refresh failed: {exc}")
                print("     • invalid_grant → Refresh token expired or revoked")

    separator()
    print("\n  🎉 ROPC / Password Grant flow completed successfully!\n")


if __name__ == "__main__":
    main()
