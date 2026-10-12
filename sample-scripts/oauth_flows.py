# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — OAuth 2.0 Flows
=============================

Demonstrates three grant types in sequence:
  1. Password Grant          — user (subject) token
  2. Client Credentials      — actor (service) token
  3. Token Exchange          — delegated token (subject + actor)

Environment variables (sample-scripts/.env)
-------------------------------------------
    IBM_VERIFY_TENANT_URL
    IBM_AUTHZ_HEADER
    IBM_USER_CLIENT_ID / IBM_USER_CLIENT_SECRET / IBM_USERNAME / IBM_PASSWORD
    IBM_ACTOR_CLIENT_ID / IBM_ACTOR_CLIENT_SECRET
    IBM_EXCHANGE_CLIENT_ID / IBM_EXCHANGE_CLIENT_SECRET

Usage
-----
    cd verify-auth-python
    python sample-scripts/oauth_flows.py
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL   = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME      = os.getenv("IBM_VERIFY_OP_NAME", "default")
AUTHZ_HEADER = os.getenv("IBM_AUTHZ_HEADER", "")

USER_CLIENT_ID     = os.getenv("IBM_USER_CLIENT_ID", "")
USER_CLIENT_SECRET = os.getenv("IBM_USER_CLIENT_SECRET", "")
USERNAME           = os.getenv("IBM_USERNAME", "")
PASSWORD           = os.getenv("IBM_PASSWORD", "")

ACTOR_CLIENT_ID     = os.getenv("IBM_ACTOR_CLIENT_ID", "")
ACTOR_CLIENT_SECRET = os.getenv("IBM_ACTOR_CLIENT_SECRET", "")

EXCHANGE_CLIENT_ID     = os.getenv("IBM_EXCHANGE_CLIENT_ID", "")
EXCHANGE_CLIENT_SECRET = os.getenv("IBM_EXCHANGE_CLIENT_SECRET", "")


def validate() -> None:
    missing = [k for k, v in {
        "IBM_VERIFY_TENANT_URL":   TENANT_URL,
        "IBM_USER_CLIENT_ID":      USER_CLIENT_ID,
        "IBM_USER_CLIENT_SECRET":  USER_CLIENT_SECRET,
        "IBM_USERNAME":            USERNAME,
        "IBM_PASSWORD":            PASSWORD,
        "IBM_ACTOR_CLIENT_ID":     ACTOR_CLIENT_ID,
        "IBM_ACTOR_CLIENT_SECRET": ACTOR_CLIENT_SECRET,
        "IBM_EXCHANGE_CLIENT_ID":  EXCHANGE_CLIENT_ID,
        "IBM_EXCHANGE_CLIENT_SECRET": EXCHANGE_CLIENT_SECRET,
    }.items() if not v]
    if missing:
        print("Missing required .env variables:")
        for m in missing:
            print(f"  • {m}")
        sys.exit(1)


def sep(title: str) -> None:
    pad = (60 - len(title) - 2) // 2
    print(f"\n{'─' * pad} {title} {'─' * pad}")


def main() -> None:
    validate()

    client = OAuthClient(base_url=TENANT_URL)

    sep("OIDC Discovery")
    try:
        meta = client.load_discovery(op_name=OP_NAME)
        print(f"  Token endpoint : {meta.get('token_endpoint')}")
    except Exception as exc:
        print(f"  Discovery failed ({exc}) — using default paths")

    # ── 1. Password Grant ─────────────────────────────────────────────────────
    sep("Step 1 — Password Grant (subject token)")
    print(f"  client_id : {USER_CLIENT_ID}")
    print(f"  username  : {USERNAME}")
    try:
        user_token = client.password_grant(
            client_id=USER_CLIENT_ID,
            client_secret=USER_CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            scope="openid profile email",
        )
        print(f"  access_token : {user_token['access_token'][:60]}...")
        print(f"  expires_in   : {user_token.get('expires_in')} s")
        if user_token.get("refresh_token"):
            print(f"  refresh_token: {str(user_token['refresh_token'])[:40]}...")
    except VerifyError as exc:
        print(f"  FAILED: {exc}")
        sys.exit(1)

    # ── 2. Client Credentials ─────────────────────────────────────────────────
    sep("Step 2 — Client Credentials (actor token)")
    print(f"  client_id : {ACTOR_CLIENT_ID}")
    try:
        actor_token = client.client_credentials(
            client_id=ACTOR_CLIENT_ID,
            client_secret=ACTOR_CLIENT_SECRET,
            scope="openid",
            authorization_header=AUTHZ_HEADER,
        )
        print(f"  access_token : {actor_token['access_token'][:60]}...")
        print(f"  expires_in   : {actor_token.get('expires_in')} s")
    except VerifyError as exc:
        print(f"  FAILED: {exc}")
        sys.exit(1)

    # ── 3. Token Exchange ─────────────────────────────────────────────────────
    sep("Step 3 — Token Exchange (delegated token)")
    print(f"  client_id : {EXCHANGE_CLIENT_ID}")
    try:
        exchanged = client.token_exchange(
            client_id=EXCHANGE_CLIENT_ID,
            client_secret=EXCHANGE_CLIENT_SECRET,
            subject_token=user_token["access_token"],
            actor_token=actor_token["access_token"],
        )
        print(f"  access_token : {exchanged['access_token'][:60]}...")
        print(f"  expires_in   : {exchanged.get('expires_in')} s")
    except VerifyError as exc:
        print(f"  FAILED: {exc}")
        sys.exit(1)

    sep("Done")
    print("  All three flows completed successfully.\n")


if __name__ == "__main__":
    main()
