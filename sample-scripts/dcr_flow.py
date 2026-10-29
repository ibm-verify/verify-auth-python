# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Dynamic Client Registration Flow (RFC 7591 / RFC 7592)
===================================================================

Demonstrates the full DCR lifecycle using the IBM Verify Python SDK:

  Step 0 — Load OIDC discovery (resolves the registration_endpoint)
  Step 1 — Register a new OAuth client       (RFC 7591 POST)
  Step 2 — Read the registered client back   (RFC 7592 GET)
  Step 3 — Update the client name/metadata   (RFC 7592 PUT)
  Step 4 — Delete the client                 (RFC 7592 DELETE)

Prerequisites — IBM Verify tenant setup
----------------------------------------
You need an admin-level access token (IAT) to authorise the POST /register
request.  Obtain one using the Client Credentials grant from an existing
API client that has the "Manage applications" or equivalent admin scope.

1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin
2. Navigate to Security → API clients
3. Pick (or create) an API client that can manage applications.
4. Use the Client Credentials grant to get an access token — that token is
   your IBM_DCR_INITIAL_ACCESS_TOKEN value.
5. Confirm that dynamic registration is enabled on the tenant:
      Security → Identity providers → <your IdP> → Advanced → Dynamic registration

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_DCR_INITIAL_ACCESS_TOKEN=<admin-access-token>

    # Optional — override the registration endpoint if your tenant uses a
    # non-standard path (leave blank to use discovery or the SDK default).
    IBM_DCR_REGISTRATION_ENDPOINT=

Common errors
-------------
• 401 invalid_token      → IAT is missing, expired, or lacks permission
• 400 invalid_client_metadata → One of the metadata fields is unsupported
• 403                    → Dynamic registration is disabled on the tenant
• 404 (on read/update/delete) → client_id no longer exists

Usage
-----
    cd verify-auth-python
    python sample-scripts/dcr_flow.py
"""

import os
import sys
from typing import Any

from dotenv import load_dotenv

# ── SDK imports ───────────────────────────────────────────────────────────────
from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL        = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME           = os.getenv("IBM_VERIFY_OP_NAME", "default")
REGISTRATION_EP   = os.getenv("IBM_DCR_REGISTRATION_ENDPOINT") or None  # None = auto-resolve

# API client used to mint a fresh IAT on every run.
# These map to IBM_CLIENT_ID / IBM_CLIENT_SECRET in .env — the same "API Client"
# credentials already used for other sample scripts.
API_CLIENT_ID     = os.getenv("IBM_CLIENT_ID", "")
API_CLIENT_SECRET = os.getenv("IBM_CLIENT_SECRET", "")

# ── Client metadata to register ───────────────────────────────────────────────
# Adjust these values to match what your IBM Verify tenant accepts.
#
# NOTE: Some IBM Verify builds require redirect_uris even for
# client_credentials-only clients.  If you get a 400, try adding:
#   "redirect_uris": ["https://placeholder.example.com/callback"],
CLIENT_METADATA: dict[str, Any] = {
    "client_name": "DCR Sample App",
    "grant_types": ["client_credentials"],
    "response_types": ["token"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid",
}

# ── Updated metadata for step 3 ───────────────────────────────────────────────
# Will be merged with the full document returned by read_client (PUT semantics).
UPDATED_CLIENT_NAME = "DCR Sample App (updated)"


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
        "IBM_VERIFY_TENANT_URL": TENANT_URL,
        "IBM_CLIENT_ID":         API_CLIENT_ID,
        "IBM_CLIENT_SECRET":     API_CLIENT_SECRET,
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


def fetch_iat(client: OAuthClient) -> str:
    """Mint a fresh Initial Access Token via Client Credentials.

    Uses IBM_CLIENT_ID / IBM_CLIENT_SECRET.  The token is passed as
    ``Authorization: Bearer <iat>`` on every POST to the registration endpoint.
    Fetching it fresh every run avoids stale-token 400/401 errors.
    """
    import base64
    b64 = base64.b64encode(f"{API_CLIENT_ID}:{API_CLIENT_SECRET}".encode()).decode()
    try:
        token = client.client_credentials(
            client_id=API_CLIENT_ID,
            client_secret=API_CLIENT_SECRET,
            scope="openid",
            authorization_header=f"Basic {b64}",
        )
    except VerifyError as exc:
        print(f"\n  ❌ Could not obtain IAT: {exc}")
        print("\n  💡 Check IBM_CLIENT_ID and IBM_CLIENT_SECRET in your .env")
        sys.exit(1)
    return str(token["access_token"])


def display_client_info(info: dict[str, Any], label: str = "Client") -> None:
    """Print the most useful fields from a client info response."""
    print(f"\n  ✅ {label}")
    print(f"     client_id                : {info.get('client_id', 'N/A')}")
    if info.get("client_secret"):
        secret = str(info["client_secret"])
        print(f"     client_secret            : {secret[:8]}{'*' * max(0, len(secret) - 8)}")
    print(f"     client_name              : {info.get('client_name', 'N/A')}")
    print(f"     grant_types              : {info.get('grant_types', 'N/A')}")
    print(f"     token_endpoint_auth_method: {info.get('token_endpoint_auth_method', 'N/A')}")
    if info.get("registration_client_uri"):
        print(f"     registration_client_uri  : {info['registration_client_uri']}")
    if info.get("registration_access_token"):
        rat = str(info["registration_access_token"])
        print(f"     registration_access_token: {rat[:16]}...")


# ── Main flow ─────────────────────────────────────────────────────────────────

def main() -> None:
    validate_config()

    print("\n" + "=" * 66)
    print("  IBM Verify — Dynamic Client Registration (RFC 7591 / RFC 7592)")
    print("=" * 66)

    # ── Initialise SDK client ─────────────────────────────────────────────────
    client = OAuthClient(base_url=TENANT_URL)

    # ── Step 0 — OIDC Discovery ───────────────────────────────────────────────
    separator("STEP 0 — Load OIDC Discovery")
    print(f"  Tenant  : {TENANT_URL}")
    print(f"  OP name : {OP_NAME}")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print("  ✅ Discovery loaded")
        print(f"     Token endpoint        : {metadata.get('token_endpoint')}")
        reg_ep = metadata.get("registration_endpoint")
        if reg_ep:
            print(f"     Registration endpoint : {reg_ep}")
        else:
            print("     Registration endpoint : (not in discovery — using SDK default)")
    except Exception as exc:
        print(f"  ⚠️  Discovery failed ({exc}) — falling back to default paths")

    if REGISTRATION_EP:
        print(f"\n  ℹ️  Using explicit registration endpoint override: {REGISTRATION_EP}")

    # ── Step 0b — Mint a fresh IAT ───────────────────────────────────────────
    separator("STEP 0b — Obtain Initial Access Token")
    print("  Fetching fresh IAT via client_credentials")
    print(f"  API client_id : {API_CLIENT_ID}")
    iat = fetch_iat(client)
    print(f"  ✅ IAT obtained  : {iat[:20]}...")

    # ── Step 1 — Register a new client ───────────────────────────────────────
    separator("STEP 1 — Register Client  (RFC 7591 POST)")
    print("  Metadata to register:")
    for k, v in CLIENT_METADATA.items():
        print(f"     {k:<34}: {v}")
    print("\n  Sending POST to registration endpoint...")

    try:
        reg = client.register_client(
            client_metadata=CLIENT_METADATA,
            initial_access_token=iat,
            registration_endpoint=REGISTRATION_EP,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Registration failed (HTTP {exc.status_code})")
        print(f"     Server response: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 401 → IAT is missing, expired, or lacks admin scope")
        print("     • 400 → A metadata field is invalid, unsupported, or missing")
        print("            → Common fix: add  \"redirect_uris\": [\"https://placeholder.example.com/callback\"]")
        print("            → Common fix: remove  \"scope\": \"openid\"  (some builds reject it)")
        print("            → Common fix: ensure  \"response_types\": [\"token\"]  is present")
        print("     • 403 → Dynamic registration is disabled on this tenant")
        print("     • Check: Security → Identity providers → Advanced → Dynamic registration")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    display_client_info(reg, "Client registered successfully")

    # Capture the credentials needed for steps 2–4
    client_id = reg["client_id"]
    rat        = reg["registration_access_token"]   # Registration Access Token
    rcu        = reg["registration_client_uri"]      # Registration Client URI

    # ── Step 2 — Read the client back ────────────────────────────────────────
    separator("STEP 2 — Read Client  (RFC 7592 GET)")
    print(f"  Fetching current metadata for client_id: {client_id}")

    try:
        info = client.read_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Read failed: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 401 → Registration access token expired or revoked")
        print("     • 404 → Client no longer exists")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    display_client_info(info, "Current client metadata")
    print("\n  Full response from server (all fields):")
    for k, v in info.items():
        print(f"     {k}: {v}")

    # RFC 7592 rotates the RAT on every successful call — always use the latest.
    rat = info.get("registration_access_token", rat)

    # ── Step 3 — Update the client ────────────────────────────────────────────
    separator("STEP 3 — Update Client  (RFC 7592 PUT)")
    print(f"  Updating client_name to: '{UPDATED_CLIENT_NAME}'")
    print("  (Full document PUT — all other fields preserved)")

    # Build the updated document: take what the server returned, update the name.
    updated_metadata = {**info, "client_name": UPDATED_CLIENT_NAME}

    # Strip ALL server-managed / read-only fields IBM Verify rejects on PUT.
    # This list covers the full set returned by the IBM Verify client_registration endpoint.
    SERVER_READONLY_FIELDS = (
        "client_id",
        "client_secret",
        "client_id_issued_at",
        "client_secret_expires_at",
        "registration_access_token",
        "registration_client_uri",
    )
    for field in SERVER_READONLY_FIELDS:
        updated_metadata.pop(field, None)

    print("\n  Sending PUT body (fields):")
    for k, v in updated_metadata.items():
        print(f"     {k}: {v}")

    try:
        updated = client.update_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
            client_metadata=updated_metadata,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Update failed: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 400 → Metadata contains an invalid or read-only field")
        print("     • 401 → Registration access token expired or revoked")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    # Rotate again so Step 4 uses the freshest token.
    rat = updated.get("registration_access_token", rat)

    new_name = updated.get("client_name", "N/A")
    if new_name == UPDATED_CLIENT_NAME:
        print(f"\n  ✅ client_name updated successfully → '{new_name}'")
    else:
        print(f"\n  ⚠️  client_name in response: '{new_name}' (expected '{UPDATED_CLIENT_NAME}')")

    # ── Step 3b — Verify the registered client can actually get a token ───────
    separator("STEP 3b — Verify: use the new client to get a token")
    print("  Attempting client_credentials with the just-registered client...")
    print(f"  client_id : {client_id}")
    reg_secret = reg.get("client_secret", "")
    if not reg_secret:
        print("  ⚠️  No client_secret in registration response — skipping token test")
        print("      (public clients or tls_client_auth clients have no secret)")
    else:
        import base64
        b64 = base64.b64encode(f"{client_id}:{reg_secret}".encode()).decode()
        try:
            new_token = client.client_credentials(
                client_id=client_id,
                client_secret=reg_secret,
                scope="openid",
                authorization_header=f"Basic {b64}",
            )
            at = str(new_token.get("access_token", ""))
            print("\n  ✅ Token obtained using registered client!")
            print(f"     access_token : {at[:40]}...")
            print(f"     token_type   : {new_token.get('token_type')}")
            print(f"     expires_in   : {new_token.get('expires_in')} s")
            print("\n  ✅ DCR is working — a client registered dynamically")
            print("     can authenticate and receive tokens from the tenant.")
        except VerifyError as exc:
            print(f"\n  ❌ Token request with new client failed: {exc}")
            print("     The client was registered but cannot authenticate yet.")
            print("     💡 Check the grant types and scopes on the tenant.")

    # ── Step 4 — Delete the client ────────────────────────────────────────────
    separator("STEP 4 — Delete Client  (RFC 7592 DELETE)")
    print(f"  About to permanently delete client_id: {client_id}")

    confirm = input("\n  Confirm deletion? [y/N]: ").strip().lower()
    if confirm != "y":
        print("\n  ⏭️  Deletion skipped.")
        separator()
        print_summary(client_id, rat, rcu, deleted=False)
        return

    try:
        client.delete_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
        )
    except VerifyError as exc:
        print(f"\n  ❌ Delete failed: {exc}")
        print("\n  💡 Troubleshooting:")
        print("     • 401 → Registration access token expired or revoked")
        print("     • 404 → Client already deleted or not found")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        sys.exit(1)

    print("\n  ✅ Client deleted (HTTP 204)")

    # Verify deletion — a GET after DELETE should return 404
    separator("STEP 4b — Verify Deletion  (expect 404)")
    print("  Attempting to read deleted client — expecting a 404...")
    try:
        client.read_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
        )
        print("  ⚠️  Client still readable after deletion (unexpected)")
    except VerifyError as exc:
        if exc.status_code == 404:
            print("  ✅ Got expected 404 — client is gone")
        else:
            print(f"  ⚠️  Got {exc.status_code} instead of 404: {exc}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(client_id, rat, rcu, deleted=True)


def print_summary(
    client_id: str,
    rat: str,
    rcu: str,
    deleted: bool,
) -> None:
    separator("Summary")
    print("\n  🎉 DCR lifecycle completed!")
    print(f"\n  Step 1 — register_client → client_id : {client_id}")
    print("  Step 2 — read_client     → metadata fetched ✅")
    print("  Step 3 — update_client   → name updated ✅")
    if deleted:
        print("  Step 4 — delete_client   → client deleted ✅")
    else:
        print("  Step 4 — delete_client   → skipped")
    print(f"\n  Registration Access Token (RAT) : {rat[:16]}...")
    print(f"  Registration Client URI  (RCU) : {rcu}")
    separator()
    print()


if __name__ == "__main__":
    main()
