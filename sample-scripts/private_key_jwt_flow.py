# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — private_key_jwt client authentication (RFC 7523 §2.2)
==================================================================

The client proves its identity with a short-lived JWT signed by its own private
key instead of a shared client secret.  Optionally the resulting token is also
DPoP-bound (RFC 9449), combining "who the client is" with "who may use the token".

Flow steps
----------
  Step 0 — OIDC discovery (token endpoint = assertion audience)
  Step 1 — Build and show the client assertion (iss/sub/aud/jti/exp)
  Step 2 — Client Credentials using private_key_jwt (+ DPoP if enabled)
  Step 3 — Introspect the token, again authenticating with private_key_jwt
  Step 4 — Negative check: assertion signed by an unregistered key is rejected

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Applications -> Add application -> OpenID Connect
2. Sign-on tab:
     Grant types                  : Client credentials
     Client authentication method : Private key JWT
     Register the public key (JWKS URI, or upload the certificate) and note its kid
     (optional) Proof-of-Possession: Enforce DPoP-bound access token
3. Save -> copy the Client ID into .env

Environment variables (.env) — see .env.example
-----------------------------------------------
    IBM_VERIFY_TENANT_URL
    IBM_PKJWT_CLIENT_ID, IBM_PKJWT_PRIVATE_KEY_PATH
    IBM_PKJWT_KID (optional), IBM_PKJWT_ALG (default RS256), IBM_PKJWT_SCOPE (default openid)
    IBM_PKJWT_DPOP=true   (optional — also request a DPoP-bound token)

Usage
-----
    cd verify-auth-python
    python sample-scripts/private_key_jwt_flow.py
"""

import base64
import json
import os
import sys

from dotenv import load_dotenv

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

TENANT_URL = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
CLIENT_ID = os.getenv("IBM_PKJWT_CLIENT_ID", "")
KEY_PATH = os.getenv("IBM_PKJWT_PRIVATE_KEY_PATH", "")
KID = os.getenv("IBM_PKJWT_KID") or None
ALG = os.getenv("IBM_PKJWT_ALG", "RS256")
SCOPE = os.getenv("IBM_PKJWT_SCOPE", "openid")
USE_DPOP = os.getenv("IBM_PKJWT_DPOP", "").lower() == "true"


def separator(title: str = "") -> None:
    width = 66
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print("─" * width)


def decode(jwt_str: str) -> tuple[dict, dict]:
    def seg(s: str) -> dict:
        return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))

    h, p, _ = jwt_str.split(".")
    return seg(h), seg(p)


def main() -> None:
    missing = [
        k
        for k, v in {
            "IBM_VERIFY_TENANT_URL": TENANT_URL,
            "IBM_PKJWT_CLIENT_ID": CLIENT_ID,
            "IBM_PKJWT_PRIVATE_KEY_PATH": KEY_PATH,
        }.items()
        if not v
    ]
    if missing:
        print("Missing required environment variables: " + ", ".join(missing))
        print("Create a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)

    key_file = (
        KEY_PATH if os.path.isabs(KEY_PATH) else os.path.join(os.path.dirname(__file__), KEY_PATH)
    )
    with open(key_file) as f:
        private_key = f.read()

    print("\n" + "=" * 66)
    print("  IBM Verify — private_key_jwt client authentication (RFC 7523)")
    print("=" * 66)

    client = OAuthClient(base_url=TENANT_URL)

    separator("STEP 0 — OIDC Discovery")
    metadata = client.load_discovery()
    token_endpoint = str(metadata.get("token_endpoint"))
    print(f"  Token endpoint           : {token_endpoint}")
    print(f"  Auth methods supported   : {metadata.get('token_endpoint_auth_methods_supported')}")
    print(
        "  Assertion algs supported : "
        f"{metadata.get('token_endpoint_auth_signing_alg_values_supported')}"
    )

    separator("STEP 1 — Client assertion")
    assertion = client.generate_client_assertion_jwt(
        client_id=CLIENT_ID,
        token_endpoint=token_endpoint,
        private_key=private_key,
        algorithm=ALG,
        key_id=KID,
    )
    header, claims = decode(assertion)
    print(f"  header : {json.dumps(header)}")
    print(f"  claims : {json.dumps(claims, indent=11)}")
    print("  No client secret is sent — only this signed, single-use, 5-minute JWT.")

    separator("STEP 2 — Client Credentials with private_key_jwt" + (" + DPoP" if USE_DPOP else ""))
    dpop_key = client.generate_dpop_key_pair("RSA") if USE_DPOP else None
    try:
        token = client.client_credentials(
            client_id=CLIENT_ID,
            scope=SCOPE,
            # With DPoP, pass a callable: if the tenant demands a DPoP nonce, the
            # automatic retry then sends a fresh assertion instead of reusing this one.
            client_assertion=(
                (
                    lambda: client.generate_client_assertion_jwt(
                        client_id=CLIENT_ID,
                        token_endpoint=token_endpoint,
                        private_key=private_key,
                        algorithm=ALG,
                        key_id=KID,
                    )
                )
                if USE_DPOP
                else assertion
            ),
            dpop_private_key=dpop_key,
        )
    except VerifyError as exc:
        print(f"\n  Token request failed (HTTP {exc.status_code}): {exc}")
        print("\n  Troubleshooting:")
        print(
            "     • invalid_client -> public key / kid not registered, wrong alg, or aud mismatch"
        )
        print("     • check the app's client authentication method is 'Private key JWT'")
        sys.exit(1)
    print(f"  token_type   : {token.get('token_type')}")
    print(f"  expires_in   : {token.get('expires_in')} s")
    print(f"  access_token : {str(token.get('access_token', ''))[:24]}…  (truncated)")

    separator("STEP 3 — Introspection (also authenticated with private_key_jwt)")
    introspection = client.introspect_token(
        token=token["access_token"],
        client_id=CLIENT_ID,
        client_assertion=client.generate_client_assertion_jwt(
            client_id=CLIENT_ID,
            token_endpoint=token_endpoint,
            private_key=private_key,
            algorithm=ALG,
            key_id=KID,
        ),
    )
    shown = {
        k: introspection.get(k)
        for k in ("active", "client_id", "scope", "exp", "token_type", "cnf")
    }
    print(json.dumps(shown, indent=4))
    if USE_DPOP and dpop_key:
        jkt = client.compute_dpop_jkt(dpop_key)
        print(f"  cnf.jkt matches DPoP key: {(introspection.get('cnf') or {}).get('jkt') == jkt}")

    separator("STEP 4 — Negative check: unregistered key")
    rogue_key = client.generate_dpop_key_pair("RSA")
    rogue = client.generate_client_assertion_jwt(
        client_id=CLIENT_ID, token_endpoint=token_endpoint, private_key=rogue_key, key_id=KID
    )
    try:
        client.client_credentials(client_id=CLIENT_ID, scope=SCOPE, client_assertion=rogue)
        print("  Rogue assertion was ACCEPTED — check the application configuration!")
    except VerifyError as exc:
        print(f"  Rejected as expected: {exc.error} — {exc.error_description}")

    separator()
    print("\n  private_key_jwt flow completed.\n")


if __name__ == "__main__":
    main()
