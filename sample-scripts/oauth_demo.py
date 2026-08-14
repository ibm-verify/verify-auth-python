# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
🎭 IBM Verify OAuth 2.0 - Interactive Demo

Supports all grant types with authorization_details (RFC 9396 RAR)
and generic extra_params across every flow.

Menu
----
 1  Password Grant
 2  Client Credentials
 3  Token Exchange
 4  Authorization Code + PKCE
 5  Device Authorization
 6  Refresh Token
 7  Token Introspection
 9  Run all OAuth demos
10  OIDC Discovery
11  JWKS Endpoint
12  JWT Bearer Token
13  ⚙️  Configure authorization_details / extra_params   ← NEW
 0  Exit
"""

import os
import sys
import json
import time
import base64
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv

# ── SDK path (works whether or not the editable install is active) ────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ibm_verify_sdk" / "src"))

from ibm_verify.oauth import (
    AuthorizationCodeMixin,
    ClientCredentialsMixin,
    DeviceCodeMixin,
    DiscoveryMixin,
    IntrospectMixin,
    JWTBearerMixin,
    OAuthBase,
    PasswordGrantMixin,
    RefreshTokenMixin,
    TokenExchangeMixin,
    build_authorization_url as _build_auth_url,
    generate_client_assertion_jwt,
    generate_jwt_bearer_assertion,
    generate_pkce_pair,
)


# ── Composite client ──────────────────────────────────────────────────────────

class OAuthClient(
    DiscoveryMixin,
    IntrospectMixin,
    PasswordGrantMixin,
    ClientCredentialsMixin,
    TokenExchangeMixin,
    RefreshTokenMixin,
    AuthorizationCodeMixin,
    DeviceCodeMixin,
    JWTBearerMixin,
    OAuthBase,
):
    """Composite OAuth client exposing all IBM Verify grant flows."""

    @staticmethod
    def generate_pkce_pair():
        return generate_pkce_pair()

    @staticmethod
    def generate_jwt_bearer_assertion(**kwargs):
        return generate_jwt_bearer_assertion(**kwargs)

    @staticmethod
    def generate_client_assertion_jwt(**kwargs):
        return generate_client_assertion_jwt(**kwargs)

    def build_authorization_url(
        self, client_id, redirect_uri, code_challenge,
        scope="openid profile email", state=None, nonce=None,
        authorization_details=None, extra_params=None,
    ):
        endpoint = self._resolve_authorize_endpoint()
        return _build_auth_url(
            authorize_endpoint=endpoint,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            scope=scope,
            state=state,
            nonce=nonce,
            authorization_details=authorization_details,
            extra_params=extra_params,
        )

    def get_discovery(self, op_name: str = "default"):
        if self._provider_metadata is None:
            self.load_discovery(op_name=op_name)
        return self._provider_metadata


# ── JWT decode helpers ────────────────────────────────────────────────────────

class _JWTUtils:
    @staticmethod
    def extract_claims(token: str) -> dict:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))

    @staticmethod
    def decode_header(token: str) -> dict:
        header = token.split(".")[0]
        header += "=" * (-len(header) % 4)
        return json.loads(base64.urlsafe_b64decode(header))


JWTUtils = _JWTUtils

# ── Environment ───────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

TENANT_URL = os.getenv("IBM_VERIFY_TENANT_URL", "").rstrip("/")
OP_NAME    = os.getenv("IBM_VERIFY_OP_NAME", "default")

CLIENT_ID     = os.getenv("IBM_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("IBM_CLIENT_SECRET", "")
USERNAME      = os.getenv("IBM_USERNAME", "")
PASSWORD      = os.getenv("IBM_PASSWORD", "")
AUTHZ_HEADER  = os.getenv("IBM_AUTHZ_HEADER", "")

USER_CLIENT_ID     = os.getenv("IBM_USER_CLIENT_ID", CLIENT_ID)
USER_CLIENT_SECRET = os.getenv("IBM_USER_CLIENT_SECRET", CLIENT_SECRET)
ACTOR_CLIENT_ID    = os.getenv("IBM_ACTOR_CLIENT_ID", CLIENT_ID)
ACTOR_CLIENT_SECRET = os.getenv("IBM_ACTOR_CLIENT_SECRET", CLIENT_SECRET)
EXCHANGE_CLIENT_ID     = os.getenv("IBM_EXCHANGE_CLIENT_ID", CLIENT_ID)
EXCHANGE_CLIENT_SECRET = os.getenv("IBM_EXCHANGE_CLIENT_SECRET", CLIENT_SECRET)

PKCE_CLIENT_ID    = os.getenv("IBM_PKCE_CLIENT_ID", CLIENT_ID)
PKCE_CLIENT_SECRET = os.getenv("IBM_PKCE_CLIENT_SECRET") or None
PKCE_REDIRECT_URI = os.getenv("IBM_PKCE_REDIRECT_URI", "http://localhost:8080/callback")

DEVICE_CLIENT_ID    = os.getenv("IBM_DEVICE_CLIENT_ID", "")
DEVICE_CLIENT_SECRET = os.getenv("IBM_DEVICE_CLIENT_SECRET") or None

JWT_CLIENT_ID    = os.getenv("IBM_JWT_CLIENT_ID", CLIENT_ID)
JWT_CLIENT_SECRET = os.getenv("IBM_JWT_CLIENT_SECRET", CLIENT_SECRET)
JWT_PRIVATE_KEY_PATH = os.getenv("IBM_JWT_PRIVATE_KEY_PATH", "certs/private-key.pem")
JWT_SUBJECT = os.getenv("IBM_JWT_SUBJECT", USERNAME)
JWT_KID     = os.getenv("IBM_JWT_KID", "")
JWT_ISSUER  = os.getenv("IBM_JWT_ISSUER", TENANT_URL)


# ── RAR / extra_params state (mutable — changed via menu option 13) ───────────
#
# DEMO_AUTHZ_DETAILS : list[dict] | None
#   Passed as authorization_details to every grant call.
#   None = field not sent (plain request).
#
# DEMO_EXTRA_PARAMS  : dict | None
#   Merged into every token/authorization request body/query.
#   None = no extra params.
#
# Edit the defaults below OR use menu option 13 at runtime.

DEMO_AUTHZ_DETAILS: Optional[List[Dict[str, Any]]] = None
# Uncomment to enable RAR for every flow:
# DEMO_AUTHZ_DETAILS = [
#     {"type": "payment_initiation",
#      "instructedAmount": {"currency": "USD", "amount": "100.00"}},
# ]

DEMO_EXTRA_PARAMS: Optional[Dict[str, Any]] = None
# Uncomment to add extra params to every request:
# DEMO_EXTRA_PARAMS = {"resource": "https://api.example.com"}


# ── Colors ────────────────────────────────────────────────────────────────────

class Colors:
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    END    = "\033[0m"


# ── Print helpers ─────────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  {Colors.BOLD}🎭  IBM Verify OAuth 2.0 — Interactive Demo{Colors.END}{Colors.CYAN}                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.END}
""")


def print_section(title: str, emoji: str = "📋"):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'═' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{emoji}  {title}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'═' * 70}{Colors.END}\n")


def print_subsection(title: str):
    print(f"\n{Colors.CYAN}{'─' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{title}{Colors.END}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.END}")


def print_success(msg: str):
    print(f"{Colors.GREEN}✅ {msg}{Colors.END}")


def print_error(msg: str):
    print(f"{Colors.RED}❌ {msg}{Colors.END}")


def print_info(msg: str):
    print(f"{Colors.CYAN}ℹ️  {msg}{Colors.END}")


def print_token_info(token: Dict[str, Any]):
    """Print the complete token response — all fields, full values, no truncation."""
    print(f"\n{Colors.GREEN}✅ Token received!{Colors.END}")
    print(f"\n{Colors.BOLD}── Full Token Response ──────────────────────────────────────────{Colors.END}")
    print(json.dumps(token, indent=2))
    print(f"{Colors.BOLD}────────────────────────────────────────────────────────────────{Colors.END}")


def print_rar_status():
    """One-line summary of current RAR / extra_params config shown in every demo."""
    ad_str = (
        f"{Colors.GREEN}SET → {json.dumps(DEMO_AUTHZ_DETAILS)[:60]}...{Colors.END}"
        if DEMO_AUTHZ_DETAILS
        else f"{Colors.YELLOW}None (not sent){Colors.END}"
    )
    ep_str = (
        f"{Colors.GREEN}SET → {DEMO_EXTRA_PARAMS}{Colors.END}"
        if DEMO_EXTRA_PARAMS
        else f"{Colors.YELLOW}None (not sent){Colors.END}"
    )
    print(f"  authorization_details : {ad_str}")
    print(f"  extra_params          : {ep_str}")


def wait_for_enter(msg: str = "Press Enter to continue..."):
    input(f"\n{Colors.YELLOW}{msg}{Colors.END}")


# ── Option 13: Configure RAR / extra_params at runtime ───────────────────────

def configure_rar_params():
    """Interactive configurator for authorization_details and extra_params."""
    global DEMO_AUTHZ_DETAILS, DEMO_EXTRA_PARAMS

    print_section("Configure authorization_details / extra_params", "⚙️")
    print_info("These values are applied to EVERY grant call in this session.\n")
    print_rar_status()

    # ── authorization_details ─────────────────────────────────────────────────
    print_subsection("authorization_details  (RFC 9396 — Rich Authorization Requests)")
    print("  Options:")
    print(f"  {Colors.BOLD}1{Colors.END}  Payment initiation  → " + json.dumps(
        [{"type": "payment_initiation", "instructedAmount": {"currency": "USD", "amount": "100.00"}}]))
    print(f"  {Colors.BOLD}2{Colors.END}  Account information → " + json.dumps(
        [{"type": "account_information", "access": {"accounts": ["read"], "balances": ["read"]}}]))
    print(f"  {Colors.BOLD}3{Colors.END}  Token exchange delegation → " + json.dumps(
        [{"type": "delegation", "delegated_to": "service-b"}]))
    print(f"  {Colors.BOLD}4{Colors.END}  Custom JSON (you type it)")
    print(f"  {Colors.BOLD}5{Colors.END}  Multiple types (payment + account)")
    print(f"  {Colors.BOLD}0{Colors.END}  Clear (send no authorization_details)")

    presets = {
        "1": [{"type": "payment_initiation",
               "instructedAmount": {"currency": "USD", "amount": "100.00"}}],
        "2": [{"type": "account_information",
               "access": {"accounts": ["read"], "balances": ["read"]}}],
        "3": [{"type": "delegation", "delegated_to": "service-b"}],
        "5": [
            {"type": "payment_initiation",
             "instructedAmount": {"currency": "USD", "amount": "100.00"}},
            {"type": "account_information",
             "access": {"accounts": ["read"], "balances": ["read"]}},
        ],
    }

    ad_choice = input(f"\n  {Colors.YELLOW}Choose [0-5, default=keep current]: {Colors.END}").strip()

    if ad_choice == "0":
        DEMO_AUTHZ_DETAILS = None
        print_success("authorization_details cleared.")
    elif ad_choice in presets:
        DEMO_AUTHZ_DETAILS = presets[ad_choice]
        print_success(f"authorization_details set: {json.dumps(DEMO_AUTHZ_DETAILS)}")
    elif ad_choice == "4":
        raw = input(
            f"  {Colors.YELLOW}Enter JSON array (e.g. [{{\"type\":\"openid\"}}]): {Colors.END}"
        ).strip()
        if raw:
            try:
                parsed = json.loads(raw)
                if not isinstance(parsed, list):
                    parsed = [parsed]
                DEMO_AUTHZ_DETAILS = parsed
                print_success(f"authorization_details set: {json.dumps(DEMO_AUTHZ_DETAILS)}")
            except json.JSONDecodeError as exc:
                print_error(f"Invalid JSON — keeping previous value. ({exc})")
        else:
            print_info("No input — keeping previous value.")
    else:
        print_info("No change to authorization_details.")

    # ── extra_params ──────────────────────────────────────────────────────────
    print_subsection("extra_params  (additional request parameters)")
    print("  Options:")
    print(f"  {Colors.BOLD}1{Colors.END}  resource indicator   → " + json.dumps(
        {"resource": "https://api.example.com"}))
    print(f"  {Colors.BOLD}2{Colors.END}  audience hint        → " + json.dumps(
        {"audience": "my-service"}))
    print(f"  {Colors.BOLD}3{Colors.END}  resource + audience  → " + json.dumps(
        {"resource": "https://api.example.com", "audience": "my-service"}))
    print(f"  {Colors.BOLD}4{Colors.END}  Custom JSON object (you type it)")
    print(f"  {Colors.BOLD}0{Colors.END}  Clear (no extra params)")

    ep_presets = {
        "1": {"resource": "https://api.example.com"},
        "2": {"audience": "my-service"},
        "3": {"resource": "https://api.example.com", "audience": "my-service"},
    }

    ep_choice = input(f"\n  {Colors.YELLOW}Choose [0-4, default=keep current]: {Colors.END}").strip()

    if ep_choice == "0":
        DEMO_EXTRA_PARAMS = None
        print_success("extra_params cleared.")
    elif ep_choice in ep_presets:
        DEMO_EXTRA_PARAMS = ep_presets[ep_choice]
        print_success(f"extra_params set: {DEMO_EXTRA_PARAMS}")
    elif ep_choice == "4":
        raw = input(
            f"  {Colors.YELLOW}Enter JSON object (e.g. {{\"key\":\"value\"}}): {Colors.END}"
        ).strip()
        if raw:
            try:
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    print_error("Must be a JSON object {{ }} — keeping previous value.")
                else:
                    DEMO_EXTRA_PARAMS = parsed
                    print_success(f"extra_params set: {DEMO_EXTRA_PARAMS}")
            except json.JSONDecodeError as exc:
                print_error(f"Invalid JSON — keeping previous value. ({exc})")
        else:
            print_info("No input — keeping previous value.")
    else:
        print_info("No change to extra_params.")

    print_subsection("Current configuration")
    print_rar_status()


# ── Grant demos ───────────────────────────────────────────────────────────────

def demo_password_grant(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("Password Grant", "🔐")
    print_rar_status()
    if not all([USER_CLIENT_ID, USER_CLIENT_SECRET, USERNAME, PASSWORD]):
        print_error("Missing configuration (IBM_USER_CLIENT_ID/SECRET, IBM_USERNAME/PASSWORD)")
        return None
    print(f"\n  Client: {USER_CLIENT_ID}   User: {USERNAME}")
    try:
        token = client.password_grant(
            client_id=USER_CLIENT_ID,
            client_secret=USER_CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
            extra_params=DEMO_EXTRA_PARAMS,              # generic extra body params
        )
        print_token_info(token)
        return token
    except Exception as e:
        print_error(f"Failed: {e}")
        return None


def demo_client_credentials(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("Client Credentials Grant", "🤖")
    print_rar_status()
    if not all([ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET]):
        print_error("Missing configuration (IBM_ACTOR_CLIENT_ID/SECRET)")
        return None
    print(f"\n  Client: {ACTOR_CLIENT_ID}   Scope: openid profile email")
    try:
        token = client.client_credentials(
            client_id=ACTOR_CLIENT_ID,
            client_secret=ACTOR_CLIENT_SECRET,
            scope="openid profile email",
            authorization_header=AUTHZ_HEADER,
            authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
            extra_params=DEMO_EXTRA_PARAMS,              # generic extra body params
        )
        print_token_info(token)
        return token
    except Exception as e:
        print_error(f"Failed: {e}")
        return None


def demo_token_exchange(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("Token Exchange Grant", "🔄")
    print_rar_status()
    if not all([USER_CLIENT_ID, USER_CLIENT_SECRET, ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET,
                EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET, USERNAME, PASSWORD]):
        print_error("Missing configuration")
        return None

    print_subsection("Step 1: Subject Token (Password Grant)")
    print(f"  Client: {USER_CLIENT_ID}")
    try:
        subject_token_resp = client.password_grant(
            client_id=USER_CLIENT_ID,
            client_secret=USER_CLIENT_SECRET,
            username=USERNAME,
            password=PASSWORD,
            authorization_header=AUTHZ_HEADER,
            authorization_details=DEMO_AUTHZ_DETAILS,
            extra_params=DEMO_EXTRA_PARAMS,
        )
        subject_token = subject_token_resp["access_token"]
        print(f"\n{Colors.BOLD}── Subject Token (Password Grant) ───────────────────────────────{Colors.END}")
        print(json.dumps(subject_token_resp, indent=2))
        print(f"{Colors.BOLD}────────────────────────────────────────────────────────────────{Colors.END}")
    except Exception as e:
        print_error(f"Failed: {e}")
        return None

    print_subsection("Step 2: Actor Token (Client Credentials)")
    print(f"  Client: {ACTOR_CLIENT_ID}")
    try:
        actor_token_resp = client.client_credentials(
            client_id=ACTOR_CLIENT_ID,
            client_secret=ACTOR_CLIENT_SECRET,
            scope="openid profile email",
            authorization_header=AUTHZ_HEADER,
            authorization_details=DEMO_AUTHZ_DETAILS,
            extra_params=DEMO_EXTRA_PARAMS,
        )
        actor_token = actor_token_resp["access_token"]
        print(f"\n{Colors.BOLD}── Actor Token (Client Credentials) ─────────────────────────────{Colors.END}")
        print(json.dumps(actor_token_resp, indent=2))
        print(f"{Colors.BOLD}────────────────────────────────────────────────────────────────{Colors.END}")
    except Exception as e:
        print_error(f"Failed: {e}")
        return None

    print_subsection("Step 3: Exchange")
    print(f"  Client: {EXCHANGE_CLIENT_ID}")
    try:
        token = client.token_exchange(
            client_id=EXCHANGE_CLIENT_ID,
            client_secret=EXCHANGE_CLIENT_SECRET,
            subject_token=subject_token,
            actor_token=actor_token,
            authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
            extra_params=DEMO_EXTRA_PARAMS,              # generic extra body params
        )
        print_token_info(token)
        return token
    except Exception as e:
        print_error(f"Failed: {e}")
        return None


def demo_authorization_code_pkce(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("Authorization Code + PKCE Flow", "🌐")
    print_rar_status()

    if not PKCE_CLIENT_ID:
        print_error("Missing IBM_PKCE_CLIENT_ID")
        return None

    parsed = urlparse(PKCE_REDIRECT_URI)
    callback_host = parsed.hostname or "localhost"
    callback_port = parsed.port or 8080
    callback_path = parsed.path or "/callback"

    print_subsection("Step 1: Generate PKCE Pair")
    code_verifier, code_challenge = OAuthClient.generate_pkce_pair()
    print_success(f"Code verifier:  {code_verifier[:40]}...")
    print_success(f"Code challenge: {code_challenge[:40]}...")

    print_subsection("Step 2: Build Authorization URL")
    # authorization_details sent as a query parameter per RFC 9396 §2.1
    auth_url = client.build_authorization_url(
        client_id=PKCE_CLIENT_ID,
        redirect_uri=PKCE_REDIRECT_URI,
        code_challenge=code_challenge,
        scope="openid profile email",
        authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR query param
        extra_params=DEMO_EXTRA_PARAMS,              # extra query params
    )
    print(f"\n{Colors.CYAN}{auth_url}{Colors.END}\n")

    if DEMO_AUTHZ_DETAILS:
        print_info(f"authorization_details in URL: {json.dumps(DEMO_AUTHZ_DETAILS)}")

    print_subsection("Step 3: Start Callback Server")
    import threading as _threading
    _callback_done = _threading.Event()
    callback_result: Dict[str, Any] = {}
    token_result: Dict[str, Any] = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal callback_result, token_result
            req = urlparse(self.path)
            if req.path != callback_path:
                self.send_response(204)
                self.end_headers()
                return

            params = parse_qs(req.query)
            code  = params.get("code",  [None])[0]
            error = params.get("error", [None])[0]
            callback_result["code"]  = code
            callback_result["error"] = error

            if error or not code:
                html = f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;text-align:center;padding:60px;color:#c0392b">
<h2>&#10007; Authorization failed</h2><p><code>{error or 'No code received'}</code></p>
</body></html>""".encode()
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                _callback_done.set()
                return

            # Exchange right here in the handler so we can render the token in browser
            try:
                tok = client.exchange_code_for_token(
                    client_id=PKCE_CLIENT_ID,
                    redirect_uri=PKCE_REDIRECT_URI,
                    code=code,
                    code_verifier=code_verifier,
                    client_secret=PKCE_CLIENT_SECRET,
                    authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
                    extra_params=DEMO_EXTRA_PARAMS,              # extra body params
                )
                token_result.update(tok)
                at  = str(tok.get("access_token", ""))
                rt  = str(tok.get("refresh_token", "")) if tok.get("refresh_token") else ""
                it  = str(tok.get("id_token", ""))     if tok.get("id_token")       else ""
                exp = tok.get("expires_in", "")
                scope = tok.get("scope", "")
                tt  = tok.get("token_type", "Bearer")
                ad  = tok.get("authorization_details")

                rows = f"""
  <tr><td>token_type</td><td><code>{tt}</code></td></tr>
  <tr><td>expires_in</td><td><code>{exp}s</code></td></tr>
  <tr><td>scope</td><td><code>{scope}</code></td></tr>
  <tr><td>access_token</td><td><code style="word-break:break-all">{at}</code></td></tr>
"""
                if rt:
                    rows += f'<tr><td>refresh_token</td><td><code style="word-break:break-all">{rt}</code></td></tr>\n'
                if it:
                    rows += f'<tr><td>id_token</td><td><code style="word-break:break-all">{it}</code></td></tr>\n'
                if ad:
                    rows += f'<tr><td>authorization_details</td><td><code style="word-break:break-all">{json.dumps(ad)}</code></td></tr>\n'

                html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>IBM Verify — Token Received</title>
<style>
  body{{font-family:-apple-system,"Segoe UI",sans-serif;background:#f0fdf4;
       display:flex;flex-direction:column;align-items:center;padding:48px 24px;margin:0}}
  .card{{background:#fff;border:1px solid #bbf7d0;border-radius:12px;
         padding:32px 40px;max-width:680px;width:100%;box-shadow:0 2px 8px rgba(0,0,0,.06)}}
  h2{{color:#15803d;margin:0 0 8px}} p.sub{{color:#555;margin:0 0 24px;font-size:14px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  td{{padding:8px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}}
  td:first-child{{font-weight:600;color:#374151;white-space:nowrap;width:160px}}
  code{{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:12px}}
</style></head>
<body><div class="card">
  <h2>&#10003; Token received!</h2>
  <p class="sub">Authorization Code + PKCE complete. Return to the terminal.</p>
  <table>{rows}</table>
  <p style="color:#6b7280;font-size:13px;margin-top:24px">You can close this tab.</p>
</div></body></html>""".encode()
            except Exception as exc:
                callback_result["exchange_error"] = str(exc)
                html = f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;text-align:center;padding:60px;color:#c0392b">
<h2>&#10007; Token exchange failed</h2><p><code>{exc}</code></p>
</body></html>""".encode()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            _callback_done.set()

        def log_message(self, format, *args):
            pass

    try:
        HTTPServer.allow_reuse_address = True
        server = HTTPServer((callback_host, callback_port), CallbackHandler)
        Thread(target=lambda: server.serve_forever(), daemon=True).start()
        time.sleep(0.3)
        print_success(f"Callback server listening on {callback_host}:{callback_port}")
    except OSError:
        print_error(f"Port {callback_port} already in use — kill it or change IBM_PKCE_REDIRECT_URI.")
        return None

    print_subsection("Step 4: User Authentication")
    open_browser = input(f"  {Colors.YELLOW}Open browser? [Y/n]: {Colors.END}").strip().lower()
    if open_browser != "n":
        webbrowser.open(auth_url)
        print_info("Browser opened — log in, approve, then return here")

    print("\n  ⏳ Waiting for callback (120s timeout)…")
    _callback_done.wait(timeout=120)
    server.shutdown()
    server.server_close()

    if callback_result.get("error"):
        print_error(f"Authorization error: {callback_result['error']}")
        return None

    auth_code = callback_result.get("code")
    if not auth_code:
        print_error("No authorization code received (timeout or no redirect).")
        return None

    print_success(f"Authorization code: {auth_code[:30]}…")

    print_subsection("Step 5: Exchange Code for Token")
    print(f"  client_id : {PKCE_CLIENT_ID}")
    print(f"  client    : {'confidential (secret)' if PKCE_CLIENT_SECRET else 'public (no secret)'}")
    if DEMO_AUTHZ_DETAILS:
        print_info(f"authorization_details: {json.dumps(DEMO_AUTHZ_DETAILS)}")
    if DEMO_EXTRA_PARAMS:
        print_info(f"extra_params: {DEMO_EXTRA_PARAMS}")

    if token_result:
        token = token_result
        print_info("Token already exchanged during callback handling.")
    else:
        if callback_result.get("exchange_error"):
            print_error(f"Handler exchange error: {callback_result['exchange_error']} — retrying…")
        try:
            token = client.exchange_code_for_token(
                client_id=PKCE_CLIENT_ID,
                redirect_uri=PKCE_REDIRECT_URI,
                code=auth_code,
                code_verifier=code_verifier,
                client_secret=PKCE_CLIENT_SECRET,
                authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
                extra_params=DEMO_EXTRA_PARAMS,              # extra body params
            )
        except Exception as e:
            print_error(f"Token exchange failed: {e}")
            return None

    print_subsection("✅ Authorization Code + PKCE Flow Complete!")
    print_token_info(token)
    return token


def demo_device_authorization(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("Device Authorization Flow", "📱")
    print_rar_status()

    if not DEVICE_CLIENT_ID:
        print_error(
            "Missing IBM_DEVICE_CLIENT_ID — add it to your .env file.\n"
            "  IBM_DEVICE_CLIENT_ID=<your-device-flow-client-id>\n"
            "  # IBM_DEVICE_CLIENT_SECRET=  ← leave commented out for a public client"
        )
        return None

    if DEVICE_CLIENT_SECRET:
        print_info(
            "Hint: if this is a public client, remove IBM_DEVICE_CLIENT_SECRET from .env "
            "(or pass client_secret=None)."
        )

    print_subsection("Step 1: Request Device & User Codes")
    print(f"  Client: {DEVICE_CLIENT_ID}   Public: {'Yes' if not DEVICE_CLIENT_SECRET else 'No'}")
    if DEMO_AUTHZ_DETAILS:
        print_info(f"authorization_details: {json.dumps(DEMO_AUTHZ_DETAILS)}")
    if DEMO_EXTRA_PARAMS:
        print_info(f"extra_params: {DEMO_EXTRA_PARAMS}")

    try:
        device_data = client.request_device_code(
            client_id=DEVICE_CLIENT_ID,
            scope="openid profile email",
            client_secret=DEVICE_CLIENT_SECRET,
            authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR (bound at Step 1)
            extra_params=DEMO_EXTRA_PARAMS,              # extra body params
        )
    except Exception as e:
        print_error(f"Failed: {e}")
        return None

    verification_uri = device_data.get("verification_uri", "")
    user_code        = device_data.get("user_code", "")
    device_code      = device_data["device_code"]
    expires_in       = device_data.get("expires_in", 300)
    interval         = device_data.get("interval", 5)

    print_subsection("Step 2: User Action Required")
    print(f"""
  ┌──────────────────────────────────────────────────────────┐
  │  1. Open: {verification_uri:<48}│
  │  2. Enter code: {Colors.BOLD}{Colors.GREEN}{user_code:<43}{Colors.END}│
  │  Expires in {expires_in}s  •  polling every {interval}s              │
  └──────────────────────────────────────────────────────────┘
""")
    open_browser = input(f"  {Colors.YELLOW}Open browser? [Y/n]: {Colors.END}").strip().lower()
    if open_browser != "n":
        webbrowser.open(verification_uri)

    print_subsection("Step 3: Polling for Token")
    print(f"  Polling every {interval}s (up to {expires_in}s)…")
    print_info("authorization_details is NOT re-sent here — it was bound at Step 1.")
    print(f"  {Colors.YELLOW}Complete the login in your browser, then wait here.{Colors.END}")
    print(f"  {Colors.YELLOW}If you skipped the browser, open the URL above manually.{Colors.END}\n")

    # Show a live counter so it's clear the script is running, not frozen
    import threading as _dthread
    _poll_done = _dthread.Event()

    def _tick():
        elapsed = 0
        while not _poll_done.is_set():
            time.sleep(1)
            elapsed += 1
            remaining = max(0, expires_in - elapsed)
            print(f"\r  ⏳ Waiting… {elapsed}s elapsed  ({remaining}s remaining)   ", end="", flush=True)
    _ticker = _dthread.Thread(target=_tick, daemon=True)
    _ticker.start()

    token = None
    try:
        token = client.poll_device_token(
            client_id=DEVICE_CLIENT_ID,
            device_code=device_code,
            interval=interval,
            expires_in=expires_in,
            client_secret=DEVICE_CLIENT_SECRET,
            # extra_params only — authorization_details is NOT sent during polling
            extra_params=DEMO_EXTRA_PARAMS,
        )
    except Exception as e:
        _poll_done.set()
        print()  # newline after the ticker
        err = str(e)
        if "timed out" in err.lower() or "expired" in err.lower():
            print_error(f"Device code expired — the user did not authenticate in time.")
            print(f"  {Colors.YELLOW}💡 Re-run this flow and complete the login within {expires_in}s.{Colors.END}")
        elif "denied" in err.lower():
            print_error(f"Access denied — the user rejected the authorization request.")
        else:
            print_error(f"Polling error: {e}")
        return None
    finally:
        _poll_done.set()

    print()  # newline after the ticker
    print_subsection("✅ Device Authorization Flow Complete!")
    print_token_info(token)
    return token


def _acquire_any_token(client: OAuthClient) -> Optional[Dict[str, Any]]:
    """Try Password Grant first, then Client Credentials, for use by Refresh/Introspect."""
    if all([USER_CLIENT_ID, USER_CLIENT_SECRET, USERNAME, PASSWORD]):
        try:
            return client.password_grant(
                client_id=USER_CLIENT_ID, client_secret=USER_CLIENT_SECRET,
                username=USERNAME, password=PASSWORD, authorization_header=AUTHZ_HEADER,
                authorization_details=DEMO_AUTHZ_DETAILS,
                extra_params=DEMO_EXTRA_PARAMS,
            )
        except Exception:
            pass
    if all([ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET]):
        try:
            return client.client_credentials(
                client_id=ACTOR_CLIENT_ID, client_secret=ACTOR_CLIENT_SECRET,
                scope="openid profile email", authorization_header=AUTHZ_HEADER,
                authorization_details=DEMO_AUTHZ_DETAILS,
                extra_params=DEMO_EXTRA_PARAMS,
            )
        except Exception:
            pass
    return None


def demo_refresh_token(
    client: OAuthClient,
    initial_token: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    print_section("Refresh Token Flow", "♻️")
    print_rar_status()

    refresh_tok = (initial_token or {}).get("refresh_token")

    if not refresh_tok:
        print_info("No refresh token from previous flow — acquiring one via Password Grant…")
        initial_token = _acquire_any_token(client)
        refresh_tok = (initial_token or {}).get("refresh_token")

    if not refresh_tok:
        print_error("Could not obtain a refresh token.")
        print_info("Run Password Grant (with refresh_token scope) or Auth Code flow first.")
        return None

    refresh_client_id     = USER_CLIENT_ID or CLIENT_ID
    refresh_client_secret = USER_CLIENT_SECRET or CLIENT_SECRET or None

    print_subsection("Refreshing Token")
    print(f"  Client:        {refresh_client_id}")
    print(f"  Refresh token: {refresh_tok}")
    if DEMO_AUTHZ_DETAILS:
        print_info(f"authorization_details: {json.dumps(DEMO_AUTHZ_DETAILS)}")
    if DEMO_EXTRA_PARAMS:
        print_info(f"extra_params: {DEMO_EXTRA_PARAMS}")

    try:
        token = client.refresh_access_token(
            client_id=refresh_client_id,
            refresh_token=refresh_tok,
            client_secret=refresh_client_secret,
            authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
            extra_params=DEMO_EXTRA_PARAMS,              # extra body params
        )
        print_token_info(token)
        return token
    except Exception as e:
        print_error(f"Failed: {e}")
        return None


def demo_token_introspection(
    client: OAuthClient,
    token: Optional[Dict[str, Any]] = None,
):
    print_section("Token Introspection", "🔍")
    # Introspection is an inspection endpoint — no authorization_details sent here.
    # authorization_details may appear inside the response if the AS echoes them.

    access_token = (token or {}).get("access_token")

    if not access_token:
        print_info("No token from previous flow — acquiring one…")
        acquired = _acquire_any_token(client)
        if acquired:
            access_token = acquired.get("access_token")
            print_success("Token acquired for introspection")

    if not access_token:
        pasted = input(
            f"  {Colors.YELLOW}Paste a token to introspect (or Enter to skip): {Colors.END}"
        ).strip()
        if not pasted:
            print_info("Skipped.")
            return
        access_token = pasted

    introspect_client_id     = CLIENT_ID  or ACTOR_CLIENT_ID
    introspect_client_secret = CLIENT_SECRET or ACTOR_CLIENT_SECRET or None

    print(f"  Token:  {access_token}")
    print(f"  Client: {introspect_client_id}")
    try:
        result = client.introspect_token(
            token=access_token, op_name=OP_NAME,
            client_id=introspect_client_id, client_secret=introspect_client_secret,
            token_type_hint="access_token",
        )
        if result.get("active"):
            print_success(
                f"Active  sub={result.get('sub')}  "
                f"client={result.get('client_id')}  "
                f"scope={result.get('scope')}"
            )
            # Show authorization_details if the AS echoes them in introspection
            if result.get("authorization_details"):
                print(f"\n  {Colors.YELLOW}📋 authorization_details in introspection response:{Colors.END}")
                print(f"  {json.dumps(result['authorization_details'], indent=4)}")
        else:
            print_info("Token is NOT active")
        show_full = input(
            f"\n{Colors.YELLOW}Show full introspection result? [y/N]: {Colors.END}"
        ).strip().lower()
        if show_full == "y":
            print(json.dumps(result, indent=2))
    except Exception as e:
        print_error(f"Failed: {e}")


def demo_oidc_discovery(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("OIDC Discovery", "🔍")
    print(f"  Endpoint: {TENANT_URL}/oauth2/.well-known/openid-configuration")
    try:
        metadata = client.load_discovery(op_name=OP_NAME)
        print_success("Discovery document retrieved")
        print(f"\n{Colors.BOLD}Key Endpoints:{Colors.END}")
        print(f"   Authorization : {metadata.get('authorization_endpoint')}")
        print(f"   Token         : {metadata.get('token_endpoint')}")
        print(f"   JWKS URI      : {metadata.get('jwks_uri')}")
        print(f"   Introspection : {metadata.get('introspection_endpoint')}")
        if metadata.get("authorization_details_types_supported"):
            print(f"   AuthZ Details : {metadata.get('authorization_details_types_supported')}")
        show_full = input(
            f"\n{Colors.YELLOW}Show complete document? [y/N]: {Colors.END}"
        ).strip().lower()
        if show_full == "y":
            print(json.dumps(dict(metadata), indent=2))
        return dict(metadata)
    except Exception as e:
        print_error(f"Failed: {e}")
        return None


def demo_jwks_endpoint(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("JWKS Endpoint", "🔑")
    print(f"  Endpoint: {TENANT_URL}/oauth2/jwks")
    try:
        jwks = client.get_jwks(op_name=OP_NAME)
        keys = jwks.get("keys", [])
        print_success(f"JWKS retrieved — {len(keys)} key(s)")
        for i, key in enumerate(keys, 1):
            print(f"\n{Colors.BOLD}Key {i}:{Colors.END}")
            print(f"   Key ID    : {key.get('kid')}")
            print(f"   Type      : {key.get('kty')}")
            print(f"   Algorithm : {key.get('alg')}")
            print(f"   Use       : {key.get('use')}")
        show_full = input(
            f"\n{Colors.YELLOW}Show complete JWKS? [y/N]: {Colors.END}"
        ).strip().lower()
        if show_full == "y":
            print(json.dumps(jwks, indent=2))
        return jwks
    except Exception as e:
        print_error(f"Failed: {e}")
        return None


def demo_jwt_bearer_token(client: OAuthClient) -> Optional[Dict[str, Any]]:
    print_section("JWT Bearer Token Flow", "🎫")
    print_rar_status()

    if not JWT_CLIENT_ID:
        print_error("Missing IBM_JWT_CLIENT_ID configuration")
        return None

    script_dir = os.path.dirname(os.path.abspath(__file__))
    key_path = (JWT_PRIVATE_KEY_PATH if os.path.isabs(JWT_PRIVATE_KEY_PATH)
                else os.path.join(script_dir, JWT_PRIVATE_KEY_PATH))

    if not os.path.exists(key_path):
        print_error(f"Private key not found: {key_path}")
        print_info("Set IBM_JWT_PRIVATE_KEY_PATH or place key at certs/private-key.pem")
        return None

    with open(key_path, "r") as f:
        private_key = f.read()

    if not JWT_KID:
        print_error("Missing IBM_JWT_KID — set it to the certificate label in Security → Certificates")
        return None

    oidc_token_endpoint = f"{TENANT_URL}/oauth2/token"

    print_subsection("Step 1: Generate JWT Bearer Assertion")
    print(f"  Client:   {JWT_CLIENT_ID}")
    print(f"  Subject:  {JWT_SUBJECT or JWT_CLIENT_ID}")
    print(f"  Audience: {oidc_token_endpoint}")
    print(f"  kid:      {JWT_KID}")
    try:
        assertion = OAuthClient.generate_jwt_bearer_assertion(
            subject=JWT_SUBJECT or JWT_CLIENT_ID,
            token_endpoint=oidc_token_endpoint,
            issuer=JWT_ISSUER,
            private_key=private_key,
            algorithm="RS256",
            key_id=JWT_KID,
        )
        print_success("JWT Bearer assertion generated")
    except Exception as e:
        print_error(f"Failed to generate assertion: {e}")
        return None

    print_subsection("Step 2: Exchange Assertion for Access Token")
    print(f"  grant_type: urn:ietf:params:oauth:grant-type:jwt-bearer")
    if DEMO_AUTHZ_DETAILS:
        print_info(f"authorization_details: {json.dumps(DEMO_AUTHZ_DETAILS)}")
    if DEMO_EXTRA_PARAMS:
        print_info(f"extra_params: {DEMO_EXTRA_PARAMS}")

    try:
        token_response = client.jwt_bearer_grant(
            assertion=assertion,
            client_id=JWT_CLIENT_ID,
            client_secret=JWT_CLIENT_SECRET or None,
            scope="openid profile email",
            token_endpoint=oidc_token_endpoint,
            authorization_details=DEMO_AUTHZ_DETAILS,   # RFC 9396 RAR
            extra_params=DEMO_EXTRA_PARAMS,              # extra body params
        )
        access_token = token_response["access_token"]
        print_token_info(token_response)
    except Exception as e:
        err_str = str(e)
        print_error(f"Failed: {err_str}")
        if "CSIAQ5223E" in err_str or "Unable to match a user account" in err_str:
            print(f"\n  {Colors.YELLOW}IBM_JWT_SUBJECT must be the IBM Verify login username")
            print(f"  (e.g. 'alice' or 'alice@example.com'), not the internal UID.{Colors.END}")
        return None

    print_subsection("Step 3: Token Details")
    parts = access_token.split(".")
    if len(parts) == 3:
        print_success(f"JWT access_token (3-part): header.payload.signature")
        print(f"  header  : {parts[0]}")
        print(f"  payload : {parts[1]}")
        print(f"  signature: {parts[2]}")
    else:
        print(f"  {Colors.CYAN}{access_token}{Colors.END}")

    print_success("JWT Bearer Token Flow Complete!")
    return {"token": access_token, "token_response": token_response}


# ── Menu ──────────────────────────────────────────────────────────────────────

def show_menu():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}Select Demo:{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.END}\n")
    print(f"{Colors.BOLD}OAuth 2.0 Grant Types:{Colors.END}")
    print(f"  1.  🔐 Password Grant")
    print(f"  2.  🤖 Client Credentials Grant")
    print(f"  3.  🔄 Token Exchange Grant")
    print(f"  4.  🌐 Authorization Code + PKCE")
    print(f"  5.  📱 Device Authorization Flow")
    print(f"  6.  ♻️  Refresh Token Flow")
    print(f"  7.  🔍 Token Introspection")
    print(f"\n{Colors.BOLD}OIDC & JWT:{Colors.END}")
    print(f"  10. 🔍 OIDC Discovery")
    print(f"  11. 🔑 JWKS Endpoint")
    print(f"  12. 🎫 JWT Bearer Token")
    print(f"\n{Colors.BOLD}Configuration:{Colors.END}")
    ad_str = (f"{Colors.GREEN}SET{Colors.END}" if DEMO_AUTHZ_DETAILS
              else f"{Colors.YELLOW}None{Colors.END}")
    ep_str = (f"{Colors.GREEN}SET{Colors.END}" if DEMO_EXTRA_PARAMS
              else f"{Colors.YELLOW}None{Colors.END}")
    print(f"  13. ⚙️  Configure authorization_details [{ad_str}] / extra_params [{ep_str}]")
    print(f"\n{Colors.BOLD}Utilities:{Colors.END}")
    print(f"  9.  🎯 Run All OAuth Demos")
    print(f"  0.  🚪 Exit")
    print(f"\n{Colors.CYAN}{'─' * 70}{Colors.END}")


def main():
    global DEMO_AUTHZ_DETAILS, DEMO_EXTRA_PARAMS

    print_banner()

    if not TENANT_URL:
        print_error("Missing IBM_VERIFY_TENANT_URL — add it to sample-scripts/.env and re-run.")
        sys.exit(1)

    print_success(f"Connected to: {TENANT_URL}")

    client = OAuthClient(base_url=TENANT_URL)

    try:
        client.load_discovery(op_name=OP_NAME)
        print_success("OIDC Discovery loaded")
    except Exception:
        print_info("Discovery unavailable — using default endpoints")

    # ── Prompt to configure RAR at startup ───────────────────────────────────
    print(f"\n{Colors.YELLOW}Configure authorization_details + extra_params before starting?{Colors.END}")
    setup_now = input(f"  [y/N]: ").strip().lower()
    if setup_now == "y":
        configure_rar_params()

    last_token: Optional[Dict[str, Any]] = None

    while True:
        show_menu()
        choice = input(f"\n{Colors.YELLOW}Choice: {Colors.END}").strip()

        if choice == "0":
            print(f"\n{Colors.GREEN}👋 Thanks!{Colors.END}\n")
            break
        elif choice == "1":
            last_token = demo_password_grant(client)
        elif choice == "2":
            last_token = demo_client_credentials(client)
        elif choice == "3":
            last_token = demo_token_exchange(client)
        elif choice == "4":
            last_token = demo_authorization_code_pkce(client)
        elif choice == "5":
            last_token = demo_device_authorization(client)
        elif choice == "6":
            last_token = demo_refresh_token(client, last_token)
        elif choice == "7":
            demo_token_introspection(client, last_token)
        elif choice == "9":
            print_info("Running all OAuth demos…")
            last_token = demo_password_grant(client);      wait_for_enter()
            demo_client_credentials(client);               wait_for_enter()
            demo_token_exchange(client);                   wait_for_enter()
            demo_authorization_code_pkce(client);          wait_for_enter()
            demo_device_authorization(client);             wait_for_enter()
            demo_refresh_token(client, last_token);        wait_for_enter()
            demo_token_introspection(client, last_token);  wait_for_enter()
            demo_oidc_discovery(client);                   wait_for_enter()
            demo_jwks_endpoint(client);                    wait_for_enter()
        elif choice == "10":
            demo_oidc_discovery(client)
        elif choice == "11":
            demo_jwks_endpoint(client)
        elif choice == "12":
            last_token = demo_jwt_bearer_token(client)
        elif choice == "13":
            configure_rar_params()
        else:
            print_info(f"Unknown option '{choice}' — try again.")


if __name__ == "__main__":
    main()
