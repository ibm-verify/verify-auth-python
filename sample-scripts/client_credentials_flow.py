# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Client Credentials Flow (RFC 6749 §4.4)
=====================================================

Demonstrates the Client Credentials grant using the IBM Verify Python SDK.
This is the standard machine-to-machine (service-to-service) flow — no user
interaction is required.

Flow steps
----------
  Step 0 — OIDC discovery (resolves the token endpoint)
  Step 1 — Obtain an access token via client_credentials
  Step 2 — Introspect the token to confirm it is active

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin
2. Navigate to Security → API clients  (or Applications → Add → Custom → OIDC)
3. Fill in:
     General tab:
       Application name : Client Credentials App
       Company name     : <your org>
     Sign-on tab:
       Grant types      : ✅ Client credentials
       Client auth      : Client secret (basic)  OR  Client secret (post)
       Scopes           : openid
4. Save → copy the Client ID and Client Secret into .env

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_ACTOR_CLIENT_ID=your-client-id
    IBM_ACTOR_CLIENT_SECRET=your-client-secret
    IBM_ACTOR_SCOPE=openid          # space-separated scopes

Common errors
-------------
• 401 invalid_client      → Wrong client_id or client_secret
• 400 invalid_scope       → Requested scope not configured on the client
• 400 unauthorized_client → Grant type not enabled on this client

Usage
-----
    cd verify-auth-python
    python sample-scripts/client_credentials_flow.py
"""

import os
import sys
import json

from dotenv import load_dotenv

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID     = os.getenv("IBM_ACTOR_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_ACTOR_CLIENT_SECRET", "")
SCOPE         = os.getenv("IBM_ACTOR_SCOPE", "openid")

# ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────────
# The SDK JSON-encodes this automatically if you pass a list/dict.
# Set to None to make a plain request.
AUTHORIZATION_DETAILS = None
# Example:
# AUTHORIZATION_DETAILS = [
#     {"type": "account_information", "actions": ["read"]},
#     {"type": "payment_initiation",  "instructedAmount": {"currency": "USD", "amount": "50.00"}},
# ]

# ── Optional: extra body parameters ───────────────────────────────────────────
# Merged verbatim into the token request body.  Set to None if not needed.
EXTRA_PARAMS = None
# Example:
# EXTRA_PARAMS = {
#     "resource": "https://api.example.com",   # RFC 8707 resource indicator
#     "audience": "my-backend-service",        # audience hint
# }


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
        "IBM_VERIFY_TENANT_URL":   TENANT_URL,
        "IBM_ACTOR_CLIENT_ID":     CLIENT_ID,
        "IBM_ACTOR_CLIENT_SECRET": CLIENT_SECRET,
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


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    print("\n" + "=" * 66)
    print("  IBM Verify — Client Credentials Flow (RFC 6749 §4.4)")
    print("=" * 66)

    import base64
    authz_header = "Basic " + base64.b64encode(
        f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    ).decode()

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

    # ── Step 1 — Client Credentials ───────────────────────────────────────────
    separator("STEP 1 — Client Credentials Grant")
    print(f"  client_id  : {CLIENT_ID}")
    print(f"  scope      : {SCOPE}")
    if AUTHORIZATION_DETAILS:
        print(f"  authz_details : {json.dumps(AUTHORIZATION_DETAILS)}")
    if EXTRA_PARAMS:
        print(f"  extra_params  : {EXTRA_PARAMS}")

    try:
        token = client.client_credentials(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=SCOPE,
            authorization_header=authz_header,
            authorization_details=AUTHORIZATION_DETAILS,
            extra_params=EXTRA_PARAMS,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Token request failed (HTTP {exc.status_code}): {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 401 → Wrong client_id or client_secret")
        print("     • 400 unauthorized_client → Grant type not enabled on this client")
        print("     • 400 invalid_scope → Scope not configured on the client")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    print(f"\n  ✅ Token obtained!")
    print(f"     token_type   : {token.get('token_type')}")
    print(f"     expires_in   : {token.get('expires_in')} s")
    print(f"     scope        : {token.get('scope')}")
    print(f"     access_token : {str(token.get('access_token', ''))[:60]}...")
    if token.get("authorization_details"):
        print(f"     authz_details: {token['authorization_details']}")

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
                print(f"     client_id : {introspection.get('client_id', 'n/a')}")
                print(f"     scope     : {introspection.get('scope', 'n/a')}")
            else:
                print("\n  ⚠️  Token is NOT active")
        except Exception as exc:
            print(f"  ⚠️  Introspection failed: {exc}")

    separator()
    print("\n  🎉 Client Credentials flow completed successfully!\n")


if __name__ == "__main__":
    main()
