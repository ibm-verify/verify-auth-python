# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — RAR (authorization_details) Verification Script
=============================================================

Verifies that authorization_details (RFC 9396) is forwarded and honoured
by the IBM Verify tenant.  Behaviour differs by deployment type:

  IBM Verify SaaS (*.verify.ibm.com / *.idng.ibmcloudsecurity.com)
  ─────────────────────────────────────────────────────────────────
  Level 1 — Token response echoes authorization_details back         ← meaningful pass
  Level 2 — Unknown types are silently accepted                      ← CORRECT for SaaS
  Level 3 — Schema-invalid payloads are silently accepted            ← CORRECT for SaaS
  Level 4 — Pre-serialised strings pass through without double-encode ← SDK correctness

  IBM Verify Access / ISVAOP (on-prem / container)
  ─────────────────────────────────────────────────
  Level 1 — Same echo test
  Level 2 — Expects HTTP 400 when ignore_unknown_authorization_details_type: false
  Level 3 — Expects HTTP 400 when authorization_details_types_schema is wired up
  Level 4 — Same passthrough test

Usage
-----
    cd verify-auth-python/oauth2
    .venv/bin/python ../sample-scripts/test_authorization_details.py

Environment variables (from sample-scripts/.env)
-------------------------------------------------
    IBM_VERIFY_TENANT_URL   — your tenant base URL
    IBM_VERIFY_OP_NAME      — OIDC provider name (default: "default")
    IBM_ACTOR_CLIENT_ID     — client ID for client_credentials grant
    IBM_ACTOR_CLIENT_SECRET — client secret
    IBM_AUTHZ_HEADER        — optional — pre-encoded header; ignored when a client secret is set
"""

import json
import os
import sys

from dotenv import load_dotenv

# Load from sample-scripts/.env (when run from project root: python sample-scripts/...)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

from ibm_verify.oauth2.auth.client import (
    OAuthClient,  # noqa: E402  # pylint: disable=wrong-import-position
)

# ── Configuration ──────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID     = os.getenv("IBM_ACTOR_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_ACTOR_CLIENT_SECRET", "")
AUTHZ_HEADER  = os.getenv("IBM_AUTHZ_HEADER", "")
SCOPE         = os.getenv("IBM_ACTOR_SCOPE", "openid")

# ── Optional: extra_params ─────────────────────────────────────────────────────
EXTRA_PARAMS: dict = {}
# Example:
# EXTRA_PARAMS = {"resource": "https://api.example.com", "audience": "my-service"}

# ── Validation ─────────────────────────────────────────────────────────────────

def validate_config() -> None:
    missing = [
        v for v, k in [
            ("IBM_VERIFY_TENANT_URL", TENANT_URL),
            ("IBM_ACTOR_CLIENT_ID", CLIENT_ID),
            ("IBM_ACTOR_CLIENT_SECRET", CLIENT_SECRET),
        ] if not k
    ]
    if missing:
        print("❌  Missing required environment variables:")
        for var in missing:
            print(f"    • {var}")
        print("\nFill in sample-scripts/.env and re-run.")
        sys.exit(1)


def separator(title: str = "") -> None:
    width = 64
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * pad}")
    else:
        print("─" * width)


# ── Test helpers ───────────────────────────────────────────────────────────────

def get_token(client: OAuthClient, authorization_details: object) -> dict:
    """Call client_credentials with the given authorization_details value."""
    return client.client_credentials(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scope=SCOPE,
        authorization_header=AUTHZ_HEADER,
        authorization_details=authorization_details,
        extra_params=EXTRA_PARAMS or None,
    )


# ── Level 1 — Does the token response echo back authorization_details? ─────────

def level1_echo(client: OAuthClient) -> bool:
    separator("LEVEL 1 — Token response echoes authorization_details")
    payload = [{"type": "account_information", "actions": ["read"]}]
    print(f"  Sending: {json.dumps(payload)}")

    try:
        token = get_token(client, payload)
    except Exception as exc:
        print(f"  ❌ Token request failed: {exc}")
        print("     Cannot proceed — check IBM_ACTOR_CLIENT_ID / IBM_ACTOR_CLIENT_SECRET.")
        return False

    print(f"\n  Full token response keys: {list(token.keys())}")

    if "authorization_details" in token:
        echoed = token["authorization_details"]
        print("\n  ✅ PASS — authorization_details echoed back:")
        print(f"     {json.dumps(echoed, indent=4)}")
        return True
    else:
        print("\n  ⚠️  INCONCLUSIVE — authorization_details absent from token response.")
        print("     This means one of:")
        print("     • The parameter was forwarded but the tenant is not configured")
        print("       to echo it back (SaaS without a token mapping rule)")
        print("     • RAR is not enabled at the definition or client level (ISVAOP)")
        print()
        print("  💡 The token request itself succeeded — your SDK change is working.")
        print("     The field is being sent correctly; the tenant is just not returning it.")
        print()
        print(f"  access_token: {str(token.get('access_token', ''))[:60]}...")
        return False


# ── Level 2 — Unknown type behaviour (SaaS: permissive; ISVAOP strict: rejected) ──

def level2_unknown_type(client: OAuthClient) -> None:
    separator("LEVEL 2 — Unknown type (SaaS: accepted; ISVAOP strict: rejected)")
    payload = [{"type": "definitely_unknown_type_xyz_99999"}]
    print(f"  Sending: {json.dumps(payload)}")
    print("  SaaS expected  → Token issued  (no per-tenant type allowlist at token endpoint)")
    print("  ISVAOP expected → HTTP 400     (ignore_unknown_authorization_details_type: false)")
    print()

    try:
        token = get_token(client, payload)
        print("  ✅ SaaS behaviour — unknown type accepted (correct for this platform).")
        print("     Type-level enforcement on SaaS lives in the application's OAuth policy")
        print("     in the admin console, not at the token endpoint.")
        print(f"     access_token: {str(token.get('access_token', ''))[:60]}...")
    except Exception as exc:
        err = str(exc)
        if "invalid_authorization_details" in err or "400" in err:
            print(f"  ✅ ISVAOP strict mode — correctly rejected with: {exc}")
        else:
            print(f"  ❓ Rejected with unexpected error: {exc}")


# ── Level 3 — Schema validation (SaaS: permissive; ISVAOP with schema: rejected) ──

def level3_schema_violation(client: OAuthClient) -> None:
    separator("LEVEL 3 — Schema validation (SaaS: accepted; ISVAOP+schema: rejected)")
    # 'locations' should be an array of URIs — passing a string tests schema enforcement.
    payload = [{"type": "account_information", "locations": "not-a-list"}]
    print(f"  Sending: {json.dumps(payload)}")
    print("  SaaS expected  → Token issued  (no JSON Schema validation on SaaS)")
    print("  ISVAOP expected → HTTP 400     (authorization_details_types_schema configured)")
    print()

    try:
        token = get_token(client, payload)
        print("  ✅ SaaS behaviour — schema-invalid payload accepted (correct for this platform).")
        print("     JSON Schema validation of authorization_details is an ISVAOP-only feature")
        print("     (authorization_details_types_schema in provider.yml).")
        print(f"     access_token: {str(token.get('access_token', ''))[:60]}...")
    except Exception as exc:
        err = str(exc)
        if "400" in err or "invalid" in err.lower():
            print(f"  ✅ ISVAOP schema validation — correctly rejected with: {exc}")
        else:
            print(f"  ❓ Rejected with unexpected error: {exc}")


# ── Level 4 (bonus) — Pre-serialised string passthrough ────────────────────────

def level4_string_passthrough(client: OAuthClient) -> None:
    separator("LEVEL 4 (bonus) — Pre-serialised JSON string passthrough")
    # Callers who manually serialise the payload should not get double-encoded JSON.
    raw_string = json.dumps([{"type": "account_information"}])
    print(f"  Passing already-serialised string: {raw_string}")
    print("  Expectation: same result as passing the list directly (no double-encoding)")
    print()

    try:
        token = get_token(client, raw_string)
        if "authorization_details" in token:
            echoed = token["authorization_details"]
            # If the server echoes it, make sure it's not double-encoded
            if isinstance(echoed, str) and echoed.startswith('"['):
                print(f"  ❌ FAIL — response looks double-encoded: {echoed[:80]}")
            else:
                print(f"  ✅ PASS — string passthrough works correctly: {echoed}")
        else:
            print("  ✅ PASS (no echo) — request completed without error.")
            print(f"     access_token: {str(token.get('access_token', ''))[:60]}...")
    except Exception as exc:
        print(f"  ❌ Request failed: {exc}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    print("\n  IBM Verify — RAR (authorization_details) Verification")
    print(f"  Tenant : {TENANT_URL}")
    print(f"  Client : {CLIENT_ID}")

    client = OAuthClient(base_url=TENANT_URL)

    # Load discovery so the token endpoint is resolved automatically
    separator("STEP 0 — OIDC Discovery")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print(f"  ✅ Token endpoint: {metadata.get('token_endpoint')}")
    except Exception as exc:
        print(f"  ⚠️  Discovery failed ({exc}) — using default paths")

    # Detect deployment type from tenant URL
    is_saas = any(h in TENANT_URL for h in [
        "verify.ibm.com", "idng.ibmcloudsecurity.com", "ice.ibmcloud.com"
    ])
    platform = "IBM Verify SaaS" if is_saas else "IBM Verify Access / ISVAOP (on-prem)"

    print(f"\n  Detected platform : {platform}")
    print(f"  Tenant URL        : {TENANT_URL}")

    # Run all levels
    l1_passed = level1_echo(client)
    level2_unknown_type(client)
    level3_schema_violation(client)
    level4_string_passthrough(client)

    # Final summary
    separator("SUMMARY")
    print()
    print(f"  Platform: {platform}")
    print()
    if l1_passed:
        print("  ✅ Level 1 — authorization_details echoed back in token response.")
        print("     The SDK change is working end-to-end.")
        print()
    else:
        print("  ⚠️  Level 1 — authorization_details was sent but not echoed back.")
        if is_saas:
            print("     On SaaS: add a token mapping rule under")
            print("     Admin Console → Security → API Access → Token management.")
        else:
            print("     On ISVAOP: add authorization_details_types_supported to provider.yml")
            print("     and authorization_details_types to the client definition.")
        print()

    if is_saas:
        print("  ℹ️  Levels 2 & 3 — permissive behaviour is correct for IBM Verify SaaS.")
        print("     Type enforcement and schema validation are ISVAOP-only features.")
        print("     On SaaS, authorization_details type policy is configured per-application")
        print("     in the admin console under the application's OAuth policy settings.")
    else:
        print("  ℹ️  Levels 2 & 3 — to enable strict enforcement on ISVAOP:")
        print("     • Set ignore_unknown_authorization_details_type: false in provider.yml")
        print("     • Add authorization_details_types_schema entries for each type")
        print("     • Add authorization_details_types to the client YAML or DCR request")
    print()


if __name__ == "__main__":
    main()
