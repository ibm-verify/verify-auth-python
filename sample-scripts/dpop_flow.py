# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — DPoP Flow (RFC 9449, Demonstrating Proof of Possession)
=====================================================================

Demonstrates a DPoP-bound access token using the Client Credentials grant.

Flow steps
----------
  Step 0 — OIDC discovery
  Step 1 — Generate (or load) the DPoP key pair
  Step 2 — Token request with a DPoP proof  -> token_type "DPoP", cnf.jkt in the token
  Step 3 — Introspect the token and compare cnf.jkt with the local key thumbprint
  Step 4 — (optional) Call a protected resource with Authorization: DPoP + a new proof
  Step 5 — Validate that proof against the introspection result

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin as an administrator
2. Applications -> Add application -> OpenID Connect
3. Sign-on tab:
     Grant types : Client credentials (and/or Authorization code)
     Proof-of-Possession settings:
         Enforce DPoP-bound access token : enabled
         Signing algorithm for DPoP JWT  : RS256 (default)  <- key type must match
4. Save -> copy the Client ID and Client Secret into .env

Environment variables (.env) — see .env.example
-----------------------------------------------
    IBM_VERIFY_TENANT_URL, IBM_VERIFY_OP_NAME
    IBM_DPOP_CLIENT_ID, IBM_DPOP_CLIENT_SECRET, IBM_DPOP_SCOPE
    IBM_DPOP_PRIVATE_KEY_PATH   (optional)  IBM_DPOP_KEY_TYPE (RSA|EC)
    IBM_DPOP_ALGORITHM          (optional)  IBM_DPOP_RESOURCE_URL (optional)

Common errors
-------------
• 400 invalid_dpop_proof  -> proof alg does not match the app's "Signing algorithm for DPoP JWT",
                             or htu/htm differ from the real request
• 400 use_dpop_nonce      -> handled automatically (one retry with the server's DPoP-Nonce);
                             if it persists, VerifyError.dpop_nonce holds the latest value
• 400 invalid_request     -> DPoP is enforced but no DPoP header was sent
• token_type "Bearer"     -> "Enforce DPoP-bound access token" is not enabled on the app

Usage
-----
    cd verify-auth-python
    python sample-scripts/dpop_flow.py
"""

import base64
import json
import os
import sys

import httpx  # noqa: F401  (kept from the original sample)
from dotenv import load_dotenv

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError
from ibm_verify.oauth2.grant_types.dpop import InMemoryDPoPReplayCache

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID = os.getenv("IBM_DPOP_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_DPOP_CLIENT_SECRET", "")
SCOPE = os.getenv("IBM_DPOP_SCOPE", "openid")
KEY_PATH = os.getenv("IBM_DPOP_PRIVATE_KEY_PATH", "")
KEY_TYPE = os.getenv("IBM_DPOP_KEY_TYPE", "RSA").upper()
ALGORITHM = os.getenv("IBM_DPOP_ALGORITHM", "") or None
RESOURCE_URL = os.getenv("IBM_DPOP_RESOURCE_URL", "")


def separator(title: str = "") -> None:
    width = 66
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print("─" * width)


def validate_config() -> None:
    missing = [
        k
        for k, v in {
            "IBM_VERIFY_TENANT_URL": TENANT_URL,
            "IBM_DPOP_CLIENT_ID": CLIENT_ID,
            "IBM_DPOP_CLIENT_SECRET": CLIENT_SECRET,
        }.items()
        if not v
    ]
    if missing:
        print("Missing required environment variables:")
        for var in missing:
            print(f"    • {var}")
        print("\nCreate a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)
    if not TENANT_URL.startswith(("http://", "https://")):
        print("IBM_VERIFY_TENANT_URL must start with https://")
        sys.exit(1)


def main() -> None:
    validate_config()

    print("\n" + "=" * 66)
    print("  IBM Verify — DPoP Flow (RFC 9449)")
    print("=" * 66)

    client = OAuthClient(base_url=TENANT_URL)

    # ── Step 0 — Discovery ────────────────────────────────────────────────────
    separator("STEP 0 — OIDC Discovery")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print(f"  Token endpoint : {metadata.get('token_endpoint')}")
        print(f"  DPoP algs      : {metadata.get('dpop_signing_alg_values_supported', 'n/a')}")
    except Exception as exc:
        print(f"  Discovery failed ({exc}) — using default paths")

    # ── Step 1 — Key pair ─────────────────────────────────────────────────────
    separator("STEP 1 — DPoP key pair")
    if KEY_PATH:
        with open(KEY_PATH) as f:
            private_key = f.read()
        print(f"  Loaded key from {KEY_PATH}")
    else:
        private_key = client.generate_dpop_key_pair(KEY_TYPE)
        print(f"  Generated a new {KEY_TYPE} key (kept in memory only)")
    local_jkt = client.compute_dpop_jkt(private_key)
    print(f"  Key thumbprint (jkt) : {local_jkt}")

    # ── Step 2 — DPoP token request ───────────────────────────────────────────
    separator("STEP 2 — Client Credentials + DPoP proof")
    authz_header = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    try:
        token = client.client_credentials(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=SCOPE,
            authorization_header=authz_header,
            dpop_private_key=private_key,
            dpop_algorithm=ALGORITHM,
        )
    except VerifyError as exc:
        print(f"\n  Token request failed (HTTP {exc.status_code}): {exc}")
        print("\n  Troubleshooting:")
        print("     • invalid_dpop_proof -> key/alg must match 'Signing algorithm for DPoP JWT'")
        print("     • use_dpop_nonce     -> retry with the server nonce also failed")
        if exc.dpop_nonce:
            print(f"       last DPoP-Nonce from server: {exc.dpop_nonce}")
        sys.exit(1)

    print(f"  token_type   : {token.get('token_type')}")
    print(f"  expires_in   : {token.get('expires_in')} s")
    print(f"  access_token : {str(token.get('access_token', ''))[:24]}…  (truncated)")
    if str(token.get("token_type", "")).lower() != "dpop":
        print("  Token is NOT DPoP-bound — enable 'Enforce DPoP-bound access token' on the app.")

    # ── Step 3 — Introspect ───────────────────────────────────────────────────
    separator("STEP 3 — Introspection")
    try:
        introspection = client.introspect_token(
            token=token["access_token"],
            op_name=OP_NAME,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            token_type_hint="access_token",
        )
    except Exception as exc:
        print(f"  Introspection failed: {exc}")
        sys.exit(1)
    print(json.dumps(introspection, indent=4))
    cnf_jkt = (introspection.get("cnf") or {}).get("jkt")
    print(f"\n  cnf.jkt (server) : {cnf_jkt}")
    print(f"  jkt (local key)  : {local_jkt}")
    print(f"  Thumbprints match: {cnf_jkt == local_jkt}")

    # ── Step 4/5 — Protected resource call + proof validation ─────────────────
    if RESOURCE_URL:
        separator("STEP 4 — Call protected resource")
        # dpop_request() sends Authorization: DPoP + a fresh proof (with ath) and
        # retries once if the resource answers with a use_dpop_nonce challenge.
        resp = client.dpop_request(
            "GET",
            RESOURCE_URL,
            access_token=token["access_token"],
            private_key=private_key,
            algorithm=ALGORITHM,
        )
        print(f"  HTTP {resp.status_code}")
        print(f"  {resp.text[:300]}")
        sent_proof = resp.request.headers["DPoP"]

        separator("STEP 5 — Validate proof against introspection")
        replay_cache = InMemoryDPoPReplayCache()
        try:
            client.introspect_dpop_token(
                token=token["access_token"],
                dpop_proof=sent_proof,
                http_method="GET",
                http_url=RESOURCE_URL,
                replay_cache=replay_cache,
                op_name=OP_NAME,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
            )
            print("  Proof is valid (signature, ath, htm/htu, iat, cnf.jkt, jti)")
        except VerifyError as exc:
            print(f"  Proof validation failed: {exc}")
        try:
            client.introspect_dpop_token(
                token=token["access_token"],
                dpop_proof=sent_proof,
                http_method="GET",
                http_url=RESOURCE_URL,
                replay_cache=replay_cache,
                op_name=OP_NAME,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
            )
            print("  Replayed proof was ACCEPTED — unexpected")
        except VerifyError as exc:
            print(f"  Replayed proof rejected as expected: {exc.error_description}")
    else:
        print("\n  (Set IBM_DPOP_RESOURCE_URL to also exercise Authorization: DPoP on a resource.)")

    separator()
    print("\n  DPoP flow completed.\n")


if __name__ == "__main__":
    main()
