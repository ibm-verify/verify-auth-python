# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — Authorization Code + PKCE Flow (RFC 7636)
=======================================================

Demonstrates the complete Authorization Code + PKCE flow using the
IBM Verify Python SDK (authlib-powered OAuthClient).

Flow steps
----------
1. Generate a PKCE code_verifier / code_challenge pair
2. Build the IBM Verify authorization URL and open it in the browser
3. IBM Verify authenticates the user and redirects to the redirect_uri
   with ?code=<authorization_code>&state=<state>
4. Exchange the authorization code + code_verifier for tokens
5. (Optional) Introspect the access token to verify it

Prerequisites — IBM Verify tenant setup
----------------------------------------
1. Log in to https://<your-tenant>.verify.ibm.com/ui/admin
2. Navigate to Applications → Applications → Add application → Custom Application → OIDC
3. Fill in:
     General tab:
       Application name : PKCE Web App
       Application URL  : http://localhost:8080   ← required field
       Company name     : <your org>
     Sign-on tab:
       Grant types      : ✅ Authorization code
       PKCE             : ✅ Required (S256)
       Client auth      : None  (public client — no secret)
       Redirect URI     : http://localhost:8080/callback
       Scopes           : openid profile email
     Entitlements tab:
       ✅ Add the user(s) who will test this application
4. Save → copy the Client ID into .env as IBM_PKCE_CLIENT_ID

Common Errors
-------------
• "OAuth 2.0 Client does not exist" → Wrong Client ID or client not created
• "Only entitled users can single sign-on" → User not added to application entitlements
• "redirect_uri mismatch" → Redirect URI in code doesn't match IBM Verify config

Environment variables (.env)
-----------------------------
    IBM_VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
    IBM_VERIFY_OP_NAME=default
    IBM_PKCE_CLIENT_ID=your-pkce-client-id
    IBM_PKCE_REDIRECT_URI=http://localhost:8080/callback
    IBM_PKCE_SCOPE=openid profile email

Usage
-----
    cd verify-auth-python
    python sample-scripts/test_pkce_flow.py
"""

import os
import sys
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from threading import Thread

from dotenv import load_dotenv

# ── SDK imports ───────────────────────────────────────────────────────────────
from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors import VerifyError

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# ── Configuration ─────────────────────────────────────────────────────────────
TENANT_URL    = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME       = os.getenv("IBM_VERIFY_OP_NAME", "default")
CLIENT_ID     = os.getenv("IBM_PKCE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_PKCE_CLIENT_SECRET") or None  # Optional for IBM Verify
REDIRECT_URI  = os.getenv("IBM_PKCE_REDIRECT_URI", "http://localhost:8080/callback")
SCOPE         = os.getenv("IBM_PKCE_SCOPE", "openid profile email")

# ── Optional: RAR payload (RFC 9396) ──────────────────────────────────────────
# Sent as a query parameter in the authorization URL (Step 2) and in the token
# request body (Step 4).  Set to None to make plain requests.
AUTHORIZATION_DETAILS = None
# Example:
# AUTHORIZATION_DETAILS = [{"type": "account_information", "access": {"accounts": ["read"]}}]

# ── Optional: extra parameters ────────────────────────────────────────────────
# Added to the authorization URL query string (Step 2) and the token request
# body (Step 4).  Set to None if not needed.
EXTRA_PARAMS = None
# Example:
# EXTRA_PARAMS = {"login_hint": "alice@example.com", "acr_values": "urn:example:bronze"}

# Parse redirect URI to get host/port for the local callback server
_parsed      = urlparse(REDIRECT_URI)
CALLBACK_HOST = _parsed.hostname or "localhost"
CALLBACK_PORT = _parsed.port or 8080
CALLBACK_PATH = _parsed.path or "/callback"


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
        missing.append("IBM_PKCE_CLIENT_ID")
    if missing:
        print("❌  Missing required environment variables:")
        for var in missing:
            print(f"    • {var}")
        print("\nCreate a .env file (see sample-scripts/.env.example) and re-run.")
        sys.exit(1)
    
    # Validate that TENANT_URL has a protocol
    if TENANT_URL and not TENANT_URL.startswith(("http://", "https://")):
        print("❌  IBM_VERIFY_TENANT_URL must start with https:// or http://")
        print(f"    Current value: {TENANT_URL}")
        print(f"    Expected: https://{TENANT_URL}")
        sys.exit(1)


# ── Local callback server ─────────────────────────────────────────────────────

# Shared state between the HTTP handler and the main thread
_callback_result: dict = {}


class _CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that captures the OAuth callback parameters."""

    def do_GET(self) -> None:  # noqa: N802
        global _callback_result
        
        # Log the incoming request for debugging
        print(f"\n  📥 Received request: {self.path}")
        
        parsed = urlparse(self.path)
        print(f"     Path: {parsed.path}")
        print(f"     Query: {parsed.query}")
        
        # Check if this is the callback path
        if parsed.path != CALLBACK_PATH:
            print(f"  ⚠️  Path mismatch! Expected: {CALLBACK_PATH}, Got: {parsed.path}")
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h2>404 Not Found</h2></body></html>")
            return

        # Parse callback parameters
        params = parse_qs(parsed.query)
        _callback_result["code"]  = params.get("code",  [None])[0]
        _callback_result["state"] = params.get("state", [None])[0]
        _callback_result["error"] = params.get("error", [None])[0]
        
        print(f"  ✅ Callback received!")
        code = _callback_result.get("code")
        if code:
            print(f"     Code: {code[:20]}...")
        error = _callback_result.get("error")
        if error:
            print(f"     Error: {error}")

        # Send a friendly HTML response to the browser
        body = b"""
        <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2>&#10003; Authorization complete!</h2>
        <p>You can close this tab and return to the terminal.</p>
        </body></html>
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: D102, A002
        # Suppress default logging to keep output clean
        pass


def _start_callback_server() -> HTTPServer:
    """Start the callback server and ensure it's ready to accept connections."""
    import socket
    
    # Allow address reuse to avoid "Address already in use" errors
    HTTPServer.allow_reuse_address = True
    
    try:
        server = HTTPServer((CALLBACK_HOST, CALLBACK_PORT), _CallbackHandler)
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"\n  ❌ Port {CALLBACK_PORT} is already in use.")
            print(f"     Kill any process using port {CALLBACK_PORT} and try again:")
            print(f"     lsof -ti:{CALLBACK_PORT} | xargs kill -9")
            print(f"     OR change IBM_PKCE_REDIRECT_URI in .env to use a different port\n")
        raise
    
    # Use serve_forever in a thread so it can handle the request properly
    thread = Thread(target=lambda: server.serve_forever(), daemon=True)
    thread.start()
    # Give the server a moment to start listening
    import time
    time.sleep(0.5)
    return server


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
        print(f"     Authorization endpoint : {metadata.get('authorization_endpoint')}")
        print(f"     Token endpoint         : {metadata.get('token_endpoint')}")
    except Exception as exc:
        print(f"  ⚠️  Discovery failed ({exc}) — falling back to default paths")

    # ── Step 1 — Generate PKCE pair ───────────────────────────────────────────
    separator("STEP 1 — Generate PKCE Pair")
    code_verifier, code_challenge = OAuthClient.generate_pkce_pair()
    print(f"  code_verifier  : {code_verifier[:40]}...  ({len(code_verifier)} chars)")
    print(f"  code_challenge : {code_challenge[:40]}...  ({len(code_challenge)} chars)")
    print(f"  method         : S256")

    # ── Step 2 — Build authorization URL ─────────────────────────────────────
    separator("STEP 2 — Build Authorization URL")
    auth_url = client.build_authorization_url(
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        code_challenge=code_challenge,
        scope=SCOPE,
        # ── new fields ────────────────────────────────────────────────────────
        authorization_details=AUTHORIZATION_DETAILS,  # RFC 9396 RAR query param; None = skip
        extra_params=EXTRA_PARAMS,                    # extra query params; None = skip
    )
    print(f"\n  {auth_url}\n")

    # ── Start local callback server ───────────────────────────────────────────
    print(f"  🌐 Starting local callback server on {CALLBACK_HOST}:{CALLBACK_PORT} ...")
    server = _start_callback_server()

    # ── Open browser ──────────────────────────────────────────────────────────
    open_browser = input("  Open browser automatically? [Y/n]: ").strip().lower()
    if open_browser != "n":
        webbrowser.open(auth_url)
        print("  🌐 Browser opened — please log in and approve the request.")
    else:
        print("  Copy the URL above into your browser, log in, and approve.")

    # ── Step 3 — Wait for callback ────────────────────────────────────────────
    separator("STEP 3 — Waiting for IBM Verify Callback")
    print("  ⏳ Waiting for redirect to", REDIRECT_URI, "...")
    
    # Wait for the callback - the thread will handle the request
    import time
    timeout = 120  # 2 minutes timeout
    start_time = time.time()
    while not _callback_result and (time.time() - start_time) < timeout:
        time.sleep(0.5)
    
    # Shutdown the server gracefully
    server.shutdown()
    server.server_close()

    if _callback_result.get("error"):
        print(f"\n  ❌ Authorization error: {_callback_result['error']}")
        sys.exit(1)

    auth_code = _callback_result.get("code")
    if not auth_code:
        print("\n  ❌ No authorization code received in callback.")
        sys.exit(1)

    print(f"\n  ✅ Authorization code received: {auth_code[:30]}...")
    print(f"     State: {_callback_result.get('state')}")

    # ── Step 4 — Exchange code for tokens ─────────────────────────────────────
    separator("STEP 4 — Exchange Code for Tokens")
    print(f"  client_id    : {CLIENT_ID}")
    print(f"  client_secret: {'(set)' if CLIENT_SECRET else '(not set)'}")
    print(f"  redirect_uri : {REDIRECT_URI}")
    print(f"  code_verifier: {code_verifier[:30]}...")
    
    # Get the token endpoint being used
    metadata = client.get_discovery(op_name=OP_NAME)
    token_endpoint = metadata.get('token_endpoint')
    print(f"  token_endpoint: {token_endpoint}")

    try:
        token = client.exchange_code_for_token(
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            code=auth_code,
            code_verifier=code_verifier,
            client_secret=CLIENT_SECRET,
            # ── new fields ────────────────────────────────────────────────────
            authorization_details=AUTHORIZATION_DETAILS,  # RFC 9396 RAR; None = skip
            extra_params=EXTRA_PARAMS,                    # extra body params; None = skip
        )
    except VerifyError as exc:
        print(f"\n  ❌ Token exchange failed: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ❌ Unexpected error: {exc}")
        print(f"\n  💡 Troubleshooting:")
        print(f"     1. Check IBM Verify application 'Client authentication method'")
        print(f"     2. If set to 'None', the client is public (no secret needed)")
        print(f"     3. If set to 'Client secret (post)' or 'Default', you need a secret")
        print(f"     4. Generate a secret in IBM Verify and add to .env as:")
        print(f"        IBM_PKCE_CLIENT_SECRET=your-secret-here")
        sys.exit(1)

    print("\n  ✅ Tokens received!")
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
                client_secret=CLIENT_SECRET,  # Pass client_secret for introspection
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
    print("\n  🎉 Authorization Code + PKCE flow completed successfully!\n")


if __name__ == "__main__":
    main()