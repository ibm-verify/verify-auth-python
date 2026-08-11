# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Device Authorization (Device Code) Flow (RFC 8628)
===============================================================

Demonstrates the complete Device Authorization flow using the
IBM Verify Python SDK (authlib-powered OAuthClient).

Flow steps
----------
1. POST to the device_authorization endpoint → receive device_code + user_code
2. Display the verification_uri and user_code to the user
3. Poll the token endpoint every `interval` seconds until the user approves
4. Receive access_token / id_token
5. (Optional) Introspect the access token to verify it

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin
2. Navigate to Security → API clients → Add API client
   (or Applications → Applications → Add application → Custom Application
    → OIDC - Relying Party)
3. Fill in:
     General tab:
       Application name : Device Code App
       Application URL  : http://localhost        ← required field (any URL)
       Company name     : <your org>
     Sign-on tab:
       Grant types      : ✅ Device authorization
       Client auth      : None  (public client — no secret)
       Scopes           : openid profile email
4. Save → copy the Client ID into .env as IBM_DEVICE_CLIENT_ID

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_DEVICE_CLIENT_ID=your-device-client-id
    # IBM_DEVICE_CLIENT_SECRET=  # only for confidential clients
    IBM_DEVICE_SCOPE=openid profile email

Usage
-----
    cd verify-python-sdk
    python sample-scripts/test_device_code_flow.py
"""

import os
import sys
import json
import webbrowser

from dotenv import load_dotenv

# ── SDK imports ───────────────────────────────────────────────────────────────
from ibm_verify.auth.client import OAuthClient
from ibm_verify.core.errors import VerifyError

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID     = os.getenv("IBM_DEVICE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_DEVICE_CLIENT_SECRET") or None   # None for public clients
SCOPE         = os.getenv("IBM_DEVICE_SCOPE", "openid profile email")

# ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────────
# Sent in the device authorization request (Step 1).
# authorization_details is NOT re-sent during polling (Step 2) — it is bound
# to the device_code at Step 1 time.  Set to None to make a plain request.
AUTHORIZATION_DETAILS = None
# Example:
# AUTHORIZATION_DETAILS = [{"type": "payment_initiation", "instructedAmount": {"currency": "USD", "amount": "25.00"}}]

# ── Optional: extra request parameters ────────────────────────────────────────
EXTRA_PARAMS = None
# Example:
# EXTRA_PARAMS = {"resource": "https://api.example.com"}

# Extra params for the token poll request only (Step 2).
POLL_EXTRA_PARAMS = None
# Example:
# POLL_EXTRA_PARAMS = {"audience": "https://api.example.com"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def separator(title: str = "") -> None:
    width = 64
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
        missing.append("IBM_DEVICE_CLIENT_ID")
    if missing:
        print("❌  Missing required environment variables:")
        for var in missing:
            print(f"    • {var}")
        print("\nCreate a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)


def display_user_instructions(device_data: dict) -> None:
    """Print the verification URL and user_code in a clear box."""
    verification_uri          = device_data.get("verification_uri", "")
    verification_uri_complete = device_data.get("verification_uri_complete", "")
    user_code                 = device_data.get("user_code", "")
    expires_in                = device_data.get("expires_in", 300)
    interval                  = device_data.get("interval", 5)

    print(f"""
  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │  ACTION REQUIRED — Authenticate on another device        │
  │                                                          │
  │  1. Open this URL in your browser:                       │
  │     {verification_uri:<56}│
  │                                                          │
  │  2. Enter this code when prompted:                       │
  │                                                          │
  │         >>>  {user_code:<47}│
  │                                                          │""")

    if verification_uri_complete:
        short = (verification_uri_complete[:54] + "…") if len(verification_uri_complete) > 55 else verification_uri_complete
        print(f"  │  OR visit the pre-filled URL:                            │")
        print(f"  │     {short:<56}│")
        print(f"  │                                                          │")

    print(f"  │  Code expires in {expires_in}s  •  polling every {interval}s              │")
    print(f"  └──────────────────────────────────────────────────────────┘")

    # Optionally open the browser
    open_browser = input("\n  Open browser automatically? [Y/n]: ").strip().lower()
    if open_browser != "n":
        url = verification_uri_complete or verification_uri
        webbrowser.open(url)
        print(f"  🌐 Browser opened: {url}")


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    # ── Initialize SDK client ─────────────────────────────────────────────────
    client = OAuthClient(base_url=TENANT_URL)

    # Load OIDC discovery so all endpoints are resolved automatically
    separator("STEP 0 — Load OIDC Discovery")
    print(f"  Tenant  : {TENANT_URL}")
    print(f"  OP name : {OP_NAME}")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print(f"  ✅ Discovery loaded")
        print(f"     Token endpoint             : {metadata.get('token_endpoint')}")
        device_ep = metadata.get("device_authorization_endpoint")
        if device_ep:
            print(f"     Device authorization endpoint: {device_ep}")
        else:
            print(f"     Device authorization endpoint: (not in discovery — using default)")
    except Exception as exc:
        print(f"  ⚠️  Discovery failed ({exc}) — falling back to default paths")

    # ── Step 1 — Request device code ─────────────────────────────────────────
    separator("STEP 1 — Request Device & User Codes")
    print(f"  client_id : {CLIENT_ID}")
    print(f"  scope     : {SCOPE}")
    print(f"  client    : {'confidential (secret provided)' if CLIENT_SECRET else 'public (no secret)'}")

    try:
        device_data = client.request_device_code(
            client_id=CLIENT_ID,
            scope=SCOPE,
            client_secret=CLIENT_SECRET,
            # ── new fields ────────────────────────────────────────────────────
            authorization_details=AUTHORIZATION_DETAILS,  # RFC 9396 RAR; None = skip
            extra_params=EXTRA_PARAMS,                    # extra body params; None = skip
        )
    except VerifyError as exc:
        print(f"\n  ❌ IBM Verify error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    print("\n  ✅ Device authorization response:")
    print(json.dumps(device_data, indent=4))

    # ── Step 2 — Display instructions to the user ─────────────────────────────
    separator("STEP 2 — User Action Required")
    display_user_instructions(device_data)

    # ── Step 3 — Poll for token ───────────────────────────────────────────────
    separator("STEP 3 — Polling for Token")
    print(f"  Polling every {device_data.get('interval', 5)}s "
          f"(up to {device_data.get('expires_in', 300)}s) ...")
    print("  Waiting for user to authenticate in browser...\n")

    try:
        token = client.poll_device_token(
            client_id=CLIENT_ID,
            device_code=device_data["device_code"],
            interval=device_data.get("interval", 5),
            expires_in=device_data.get("expires_in", 300),
            client_secret=CLIENT_SECRET,
            # ── new fields ────────────────────────────────────────────────────
            # authorization_details is NOT sent here — it was bound at Step 1.
            extra_params=POLL_EXTRA_PARAMS,               # extra body params; None = skip
        )
    except TimeoutError as exc:
        print(f"\n  ❌ Timed out: {exc}")
        sys.exit(1)
    except PermissionError as exc:
        print(f"\n  ❌ Access denied: {exc}")
        sys.exit(1)
    except RuntimeError as exc:
        print(f"\n  ❌ Polling error: {exc}")
        sys.exit(1)
    except VerifyError as exc:
        print(f"\n  ❌ IBM Verify error: {exc}")
        sys.exit(1)

    # ── Step 4 — Display token ────────────────────────────────────────────────
    separator("STEP 4 — Token Received")
    print("\n  ✅ Authentication successful!")
    print(f"     token_type   : {token.get('token_type')}")
    print(f"     expires_in   : {token.get('expires_in')} seconds")
    print(f"     scope        : {token.get('scope')}")
    print(f"     access_token : {str(token.get('access_token', ''))[:60]}...")
    if token.get("authorization_details"):
        print(f"     authz_details: {token['authorization_details']}")
    if token.get("id_token"):
        print(f"     id_token     : {str(token.get('id_token', ''))[:60]}...")
    if token.get("refresh_token"):
        print(f"     refresh_token: {str(token.get('refresh_token', ''))[:60]}...")

    # ── Step 5 — Introspect the access token (optional) ───────────────────────
    separator("STEP 5 — Token Introspection (optional)")
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
                print(f"     Subject  : {introspection.get('sub', 'n/a')}")
                print(f"     Username : {introspection.get('username', 'n/a')}")
                print(f"     Scope    : {introspection.get('scope', 'n/a')}")
            else:
                print("\n  ⚠️  Token is NOT active")
        except Exception as exc:
            print(f"  ⚠️  Introspection failed: {exc}")

    separator()
    print("\n  🎉 Device Authorization flow completed successfully!\n")


if __name__ == "__main__":
    main()