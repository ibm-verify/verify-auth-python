# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Token Introspection (RFC 7662)
===========================================

Obtains a fresh access token via password grant, then introspects it
using the IBM Verify introspection endpoint.

Environment variables (sample-scripts/.env)
-------------------------------------------
    IBM_VERIFY_TENANT_URL
    IBM_VERIFY_OP_NAME
    IBM_USER_CLIENT_ID / IBM_USER_CLIENT_SECRET
    IBM_USERNAME / IBM_PASSWORD

Usage
-----
    cd verify-python-sdk
    python sample-scripts/introspect_token.py
"""

import os
import sys
import json
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

from ibm_verify.auth.client import OAuthClient
from ibm_verify.core.errors import VerifyError

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID     = os.getenv("IBM_USER_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_USER_CLIENT_SECRET", "")
USERNAME      = os.getenv("IBM_USERNAME", "")
PASSWORD      = os.getenv("IBM_PASSWORD", "")
AUTHZ_HEADER  = os.getenv("IBM_AUTHZ_HEADER", "")


def validate() -> None:
    missing = [k for k, v in {
        "IBM_VERIFY_TENANT_URL":  TENANT_URL,
        "IBM_USER_CLIENT_ID":     CLIENT_ID,
        "IBM_USER_CLIENT_SECRET": CLIENT_SECRET,
        "IBM_USERNAME":           USERNAME,
        "IBM_PASSWORD":           PASSWORD,
    }.items() if not v]
    if missing:
        print("Missing required .env variables:")
        for m in missing:
            print(f"  • {m}")
        sys.exit(1)


def sep(title: str = "") -> None:
    width = 60
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print("─" * width)


def main() -> None:
    validate()

    client = OAuthClient(base_url=TENANT_URL)

    sep("OIDC Discovery")
    try:
        meta = client.load_discovery(op_name=OP_NAME)
        print(f"  Token endpoint       : {meta.get('token_endpoint')}")
        print(f"  Introspection endpoint: {meta.get('introspection_endpoint')}")
    except Exception as exc:
        print(f"  Discovery failed ({exc}) — using default paths")

    # ── Step 1: obtain a token via password grant ─────────────────────────────
    sep("Step 1 — Obtain access token (password grant)")
    print(f"  client_id : {CLIENT_ID}")
    print(f"  username  : {USERNAME}")
    try:
        token_resp = client.password_grant(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            scope="openid profile email",
        )
        access_token = token_resp["access_token"]
        print(f"  access_token : {access_token[:60]}...")
        print(f"  expires_in   : {token_resp.get('expires_in')} s")
    except VerifyError as exc:
        print(f"  FAILED: {exc}")
        sys.exit(1)

    # ── Step 2: introspect the token ──────────────────────────────────────────
    sep("Step 2 — Introspect token")
    try:
        result = client.introspect_token(
            token=access_token,
            op_name=OP_NAME,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            token_type_hint="access_token",
        )
        print(json.dumps(result, indent=2))

        sep()
        if result.get("active"):
            print(f"  Token is ACTIVE")
            print(f"  Subject  : {result.get('sub', 'n/a')}")
            print(f"  Username : {result.get('username', 'n/a')}")
            print(f"  Scope    : {result.get('scope', 'n/a')}")
            print(f"  Expires  : {result.get('exp', 'n/a')}")
        else:
            print("  Token is NOT active")
    except VerifyError as exc:
        print(f"  FAILED: {exc}")
        sys.exit(1)

    sep()
    print("  Introspection complete.\n")


if __name__ == "__main__":
    main()
