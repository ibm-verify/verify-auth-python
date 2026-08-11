# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Token Exchange Flow (RFC 8693)
============================================

Demonstrates the Token Exchange grant using the IBM Verify Python SDK.
Token exchange lets a service (actor) obtain a delegated token scoped to
act on behalf of a user (subject), or to downscope / audience-restrict
an existing token.

Flow steps
----------
  Step 0 — OIDC discovery
  Step 1 — Obtain a subject token  (Password grant — the user's token)
  Step 2 — Obtain an actor token   (Client Credentials — the service's token)
  Step 3 — Exchange both for a delegated token  (Token Exchange)
  Step 4 — Introspect the exchanged token

Prerequisites — IBM Verify tenant setup
----------------------------------------
You need THREE clients configured in IBM Verify:

  Client A — subject client (Password / ROPC grant)
    • Grant types: Resource owner password credentials
    • Client auth: Client secret (post) or (basic)
    • Scopes: openid profile email

  Client B — actor client (Client Credentials)
    • Grant types: Client credentials
    • Client auth: Client secret (basic)
    • Scopes: openid

  Client C — exchange client (Token Exchange)
    • Grant types: Token exchange
    • Client auth: Client secret (basic)
    • Scopes: openid
    • In IBM Verify, Token Exchange is sometimes called "Delegation" or
      requires enabling at Security → Global settings → Token exchange.

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_AUTHZ_HEADER=Bearer <admin-or-super-token>   # used for password grant

    # Subject client (user token)
    IBM_USER_CLIENT_ID=your-user-client-id
    IBM_USER_CLIENT_SECRET=your-user-client-secret
    IBM_USERNAME=your-username
    IBM_PASSWORD=your-password

    # Actor client (service token)
    IBM_ACTOR_CLIENT_ID=your-actor-client-id
    IBM_ACTOR_CLIENT_SECRET=your-actor-client-secret

    # Exchange client
    IBM_EXCHANGE_CLIENT_ID=your-exchange-client-id
    IBM_EXCHANGE_CLIENT_SECRET=your-exchange-client-secret

Common errors
-------------
• 400 invalid_grant / unsupported_grant_type → Token exchange not enabled on the tenant
  or the exchange client does not have the "Token exchange" grant type.
• 401 invalid_client → Wrong client credentials for the exchange client.
• 400 invalid_request → subject_token or actor_token missing / invalid.

Usage
-----
    cd verify-python-sdk
    python sample-scripts/token_exchange_flow.py
"""

import os
import sys
import json
import base64

from dotenv import load_dotenv

from ibm_verify.auth.client import OAuthClient
from ibm_verify.core.errors import VerifyError

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
AUTHZ_HEADER  = os.getenv("IBM_AUTHZ_HEADER", "")

USER_CLIENT_ID     = os.getenv("IBM_USER_CLIENT_ID", "")
USER_CLIENT_SECRET = os.getenv("IBM_USER_CLIENT_SECRET", "")
USERNAME           = os.getenv("IBM_USERNAME", "")
PASSWORD           = os.getenv("IBM_PASSWORD", "")

ACTOR_CLIENT_ID     = os.getenv("IBM_ACTOR_CLIENT_ID", "")
ACTOR_CLIENT_SECRET = os.getenv("IBM_ACTOR_CLIENT_SECRET", "")

EXCHANGE_CLIENT_ID     = os.getenv("IBM_EXCHANGE_CLIENT_ID", "")
EXCHANGE_CLIENT_SECRET = os.getenv("IBM_EXCHANGE_CLIENT_SECRET", "")

# ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────────
# Sent in the token_exchange request only.  Set to None to omit.
AUTHORIZATION_DETAILS = None
# Example:
# AUTHORIZATION_DETAILS = [
#     {"type": "account_information", "actions": ["read"]},
# ]

# ── Optional: extra body parameters ───────────────────────────────────────────
# Merged verbatim into the token exchange request body.
EXTRA_PARAMS = None
# Example:
# EXTRA_PARAMS = {"resource": "https://api.example.com", "audience": "my-service"}


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
        "IBM_VERIFY_TENANT_URL":      TENANT_URL,
        "IBM_USER_CLIENT_ID":         USER_CLIENT_ID,
        "IBM_USER_CLIENT_SECRET":     USER_CLIENT_SECRET,
        "IBM_USERNAME":               USERNAME,
        "IBM_PASSWORD":               PASSWORD,
        "IBM_ACTOR_CLIENT_ID":        ACTOR_CLIENT_ID,
        "IBM_ACTOR_CLIENT_SECRET":    ACTOR_CLIENT_SECRET,
        "IBM_EXCHANGE_CLIENT_ID":     EXCHANGE_CLIENT_ID,
        "IBM_EXCHANGE_CLIENT_SECRET": EXCHANGE_CLIENT_SECRET,
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


def show_token(token: dict, label: str) -> None:
    print(f"\n  ✅ {label}")
    print(f"     token_type   : {token.get('token_type')}")
    print(f"     expires_in   : {token.get('expires_in')} s")
    print(f"     scope        : {token.get('scope')}")
    print(f"     access_token : {str(token.get('access_token', ''))[:60]}...")
    if token.get("authorization_details"):
        print(f"     authz_details: {token['authorization_details']}")


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    print("\n" + "=" * 66)
    print("  IBM Verify — Token Exchange Flow (RFC 8693)")
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

    # ── Step 1 — Subject token (Password grant) ───────────────────────────────
    separator("STEP 1 — Subject Token (Password Grant)")
    print(f"  client_id : {USER_CLIENT_ID}")
    print(f"  username  : {USERNAME}")

    try:
        subject_resp = client.password_grant(
            client_id=USER_CLIENT_ID,
            client_secret=USER_CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            scope="openid profile email",
        )
    except VerifyError as exc:
        print(f"\n  ❌ Password grant failed: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • Verify IBM_USERNAME / IBM_PASSWORD")
        print("     • Ensure ROPC grant type is enabled on IBM_USER_CLIENT_ID")
        print("     • Ensure the user is entitled to the application")
        sys.exit(1)

    show_token(subject_resp, "Subject token obtained")
    subject_token = subject_resp["access_token"]

    # ── Step 2 — Actor token (Client Credentials) ─────────────────────────────
    separator("STEP 2 — Actor Token (Client Credentials)")
    print(f"  client_id : {ACTOR_CLIENT_ID}")

    actor_authz = "Basic " + base64.b64encode(
        f"{ACTOR_CLIENT_ID}:{ACTOR_CLIENT_SECRET}".encode()
    ).decode()

    try:
        actor_resp = client.client_credentials(
            client_id=ACTOR_CLIENT_ID,
            client_secret=ACTOR_CLIENT_SECRET,
            scope="openid",
            authorization_header=actor_authz,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Client credentials failed: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • Check IBM_ACTOR_CLIENT_ID and IBM_ACTOR_CLIENT_SECRET")
        print("     • Ensure Client Credentials grant is enabled on that client")
        sys.exit(1)

    show_token(actor_resp, "Actor token obtained")
    actor_token = actor_resp["access_token"]

    # ── Step 3 — Token Exchange ───────────────────────────────────────────────
    separator("STEP 3 — Token Exchange (delegated token)")
    print(f"  exchange client_id : {EXCHANGE_CLIENT_ID}")
    print(f"  subject_token      : {subject_token[:40]}...")
    print(f"  actor_token        : {actor_token[:40]}...")
    if AUTHORIZATION_DETAILS:
        print(f"  authz_details      : {json.dumps(AUTHORIZATION_DETAILS)}")
    if EXTRA_PARAMS:
        print(f"  extra_params       : {EXTRA_PARAMS}")

    try:
        exchanged = client.token_exchange(
            client_id=EXCHANGE_CLIENT_ID,
            client_secret=EXCHANGE_CLIENT_SECRET,
            subject_token=subject_token,
            actor_token=actor_token,
            authorization_details=AUTHORIZATION_DETAILS,
            extra_params=EXTRA_PARAMS,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Token exchange failed (HTTP {exc.status_code}): {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 400 unsupported_grant_type → Token exchange not enabled on the tenant")
        print("       Check: Security → Global settings → Token exchange (IBM Verify SaaS)")
        print("     • 400 invalid_grant          → subject_token or actor_token is invalid/expired")
        print("     • 401 invalid_client         → Wrong IBM_EXCHANGE_CLIENT_ID or SECRET")
        print("     • Ensure 'Token exchange' grant is enabled on the exchange client")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    show_token(exchanged, "Delegated token obtained")

    # ── Step 4 — Introspect the exchanged token ───────────────────────────────
    separator("STEP 4 — Introspect Exchanged Token")
    do_introspect = input("  Introspect the delegated access token? [Y/n]: ").strip().lower()
    if do_introspect != "n":
        try:
            introspection = client.introspect_token(
                token=exchanged["access_token"],
                op_name=OP_NAME,
                client_id=EXCHANGE_CLIENT_ID,
                client_secret=EXCHANGE_CLIENT_SECRET,
                token_type_hint="access_token",
            )
            print("\n  Introspection response:")
            print(json.dumps(introspection, indent=4))
            if introspection.get("active"):
                print(f"\n  ✅ Token is ACTIVE")
                print(f"     sub       : {introspection.get('sub', 'n/a')}")
                print(f"     client_id : {introspection.get('client_id', 'n/a')}")
                print(f"     scope     : {introspection.get('scope', 'n/a')}")
            else:
                print("\n  ⚠️  Token is NOT active")
        except Exception as exc:
            print(f"  ⚠️  Introspection failed: {exc}")

    separator()
    print("\n  🎉 Token Exchange flow completed successfully!\n")
    print("  Summary:")
    print(f"     Subject token (user)     : {subject_token[:40]}...")
    print(f"     Actor token (service)    : {actor_token[:40]}...")
    print(f"     Delegated token          : {str(exchanged.get('access_token', ''))[:40]}...")
    print()


if __name__ == "__main__":
    main()
