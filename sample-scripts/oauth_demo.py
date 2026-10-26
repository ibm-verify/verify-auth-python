# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""
IBM Verify — verify-auth-python interactive demo
================================================

One menu for every flow the SDK supports, against your own IBM Verify tenant.

  Grants                                   Proof-of-possession & client auth
   1  Client credentials                    8  DPoP — bound token, protected API, attacks
   2  Password (ROPC)                       9  private_key_jwt — client auth, attacks
   3  Authorization code + PKCE (browser)  10  private_key_jwt + DPoP together
   4  Device authorization (2nd device)
   5  Refresh token                        Tokens & metadata
   6  Token exchange (RFC 8693)            11  Introspect the last token
   7  JWT bearer grant (RFC 7523)          12  OIDC discovery   13  JWKS
                                           14  Dynamic client registration
  Session
   r  Run ALL flows back to back (asks once about browser/device and DCR)
   t  Guided tour — every flow in five chapters, with a summary at the end
   s  Settings — DPoP on every grant, show full tokens, RAR / extra_params
   a  Run every non-interactive flow (smoke test with a summary)

Command line
------------
    python oauth_demo.py                     # interactive menu
    python oauth_demo.py --tour              # guided tour through every flow (for presenting)
    python oauth_demo.py --all               # run every flow back to back, incl. browser/device
    python oauth_demo.py --flow dpop         # run one flow and exit (good for recording)
    python oauth_demo.py --smoke             # E2E: run all non-interactive flows, exit 1 on failure
    python oauth_demo.py --smoke --include-dcr   # …also create + delete a DCR client
    Options: --no-pause  --dpop (DPoP on every grant)  --show-tokens (unmasked)

    Flow names: cc, password, pkce, device, refresh, exchange, jwt-bearer,
                dpop, pkjwt, pkjwt-dpop, introspect, discovery, jwks, dcr

Configuration: sample-scripts/.env (see .env.example). Each flow tells you which
variables it needs and is skipped if they are missing.
"""

import argparse
import base64
import json
import os
import sys
import threading
import time
import uuid
import warnings
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

import authlib.deprecate  # noqa: F401  (registers authlib's filter so ours below wins)

warnings.filterwarnings("ignore", message=r".*deprecated.*")

import httpx  # noqa: E402
from authlib.jose import JsonWebKey  # noqa: E402
from authlib.jose import jwt as authlib_jwt  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

import ibm_verify.oauth2.grant_types.base as _sdk_base  # noqa: E402
from ibm_verify.oauth2 import OAuthClient, VerifyError  # noqa: E402
from ibm_verify.oauth2.grant_types.dpop import (  # noqa: E402
    InMemoryDPoPReplayCache,
    _public_jwk,
    compute_ath,
)

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(HERE, ".env"))


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default) or default


# ── Configuration (.env) ─────────────────────────────────────────────────────
TENANT_URL = env("IBM_VERIFY_TENANT_URL").rstrip("/")
OP_NAME = env("IBM_VERIFY_OP_NAME", "default")
AUTHZ_HEADER = env("IBM_AUTHZ_HEADER")

CLIENT_ID = env("IBM_CLIENT_ID")
CLIENT_SECRET = env("IBM_CLIENT_SECRET")
USERNAME = env("IBM_USERNAME")
PASSWORD = env("IBM_PASSWORD")

USER_CLIENT_ID = env("IBM_USER_CLIENT_ID", CLIENT_ID)
USER_CLIENT_SECRET = env("IBM_USER_CLIENT_SECRET", CLIENT_SECRET)
ACTOR_CLIENT_ID = env("IBM_ACTOR_CLIENT_ID", CLIENT_ID)
ACTOR_CLIENT_SECRET = env("IBM_ACTOR_CLIENT_SECRET", CLIENT_SECRET)
ACTOR_SCOPE = env("IBM_ACTOR_SCOPE", "openid")
EXCHANGE_CLIENT_ID = env("IBM_EXCHANGE_CLIENT_ID", CLIENT_ID)
EXCHANGE_CLIENT_SECRET = env("IBM_EXCHANGE_CLIENT_SECRET", CLIENT_SECRET)

PKCE_CLIENT_ID = env("IBM_PKCE_CLIENT_ID", CLIENT_ID)
PKCE_CLIENT_SECRET = env("IBM_PKCE_CLIENT_SECRET") or None
PKCE_REDIRECT_URI = env("IBM_PKCE_REDIRECT_URI", "http://localhost:8080/callback")
PKCE_SCOPE = env("IBM_PKCE_SCOPE", "openid profile email")

DEVICE_CLIENT_ID = env("IBM_DEVICE_CLIENT_ID")
DEVICE_CLIENT_SECRET = env("IBM_DEVICE_CLIENT_SECRET") or None
DEVICE_SCOPE = env("IBM_DEVICE_SCOPE", "openid profile email")

JWT_CLIENT_ID = env("IBM_JWT_CLIENT_ID", CLIENT_ID)
JWT_CLIENT_SECRET = env("IBM_JWT_CLIENT_SECRET") or None
JWT_PRIVATE_KEY_PATH = env("IBM_JWT_PRIVATE_KEY_PATH", "certs/private-key.pem")
JWT_SUBJECT = env("IBM_JWT_SUBJECT", USERNAME)
JWT_KID = env("IBM_JWT_KID")
JWT_ISSUER = env("IBM_JWT_ISSUER", TENANT_URL)

DPOP_CLIENT_ID = env("IBM_DPOP_CLIENT_ID")
DPOP_CLIENT_SECRET = env("IBM_DPOP_CLIENT_SECRET")
DPOP_SCOPE = env("IBM_DPOP_SCOPE", "openid")
DPOP_KEY_TYPE = env("IBM_DPOP_KEY_TYPE", "RSA").upper()
DPOP_ALG = env("IBM_DPOP_ALGORITHM") or None

PKJWT_CLIENT_ID = env("IBM_PKJWT_CLIENT_ID")
PKJWT_KEY_PATH = env("IBM_PKJWT_PRIVATE_KEY_PATH")
PKJWT_KID = env("IBM_PKJWT_KID") or None
PKJWT_ALG = env("IBM_PKJWT_ALG", "RS256")
PKJWT_SCOPE = env("IBM_PKJWT_SCOPE", "openid")
PKJWT_DPOP = env("IBM_PKJWT_DPOP").lower() == "true"

DCR_INITIAL_ACCESS_TOKEN = env("IBM_DCR_INITIAL_ACCESS_TOKEN")

API_PORT = int(env("IBM_DEMO_API_PORT", "8765"))


# ══════════════════════════════════════════════════════════════════════════════
# Terminal UI
# ══════════════════════════════════════════════════════════════════════════════


class UI:
    color = sys.stdout.isatty() and not os.getenv("NO_COLOR")
    pause_enabled = True
    smoke = False
    tour = False
    run_all = False

    @classmethod
    def c(cls, code: str, text: Any) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.color else str(text)


def bold(t: Any) -> str:
    return UI.c("1", t)


def dim(t: Any) -> str:
    return UI.c("2", t)


def cyan(t: Any) -> str:
    return UI.c("36", t)


def green(t: Any) -> str:
    return UI.c("32", t)


def red(t: Any) -> str:
    return UI.c("31", t)


def yellow(t: Any) -> str:
    return UI.c("33", t)


def magenta(t: Any) -> str:
    return UI.c("35", t)


_pending_story: list[tuple[str, str]] = []


def section(title: str, subtitle: str = "") -> None:
    print("\n" + cyan("═" * 72))
    print(bold(f"  {title}"))
    if subtitle:
        print(dim(f"  {subtitle}"))
    print(cyan("═" * 72))
    if _pending_story:
        what, when = _pending_story.pop()
        print(f"  {bold('What')}  {what}")
        print(f"  {bold('When')}  {when}")


def step(title: str) -> None:
    print("\n" + bold(cyan(f"── {title} ")) + cyan("─" * max(4, 66 - len(title))))


def say(text: str) -> None:
    words, line = text.split(), ""
    for w in words:
        if len(line) + len(w) > 74:
            print(dim("  " + line))
            line = ""
        line += ("" if not line else " ") + w
    if line:
        print(dim("  " + line))


def ok(text: str) -> None:
    print(green(f"  ✔ {text}"))


def fail(text: str) -> None:
    print(red(f"  ✘ {text}"))


def warn(text: str) -> None:
    print(yellow(f"  ! {text}"))


def kv(key: str, value: Any, width: int = 20) -> None:
    print(f"  {key:<{width}} {value}")


def code(text: str) -> None:
    for line in text.strip("\n").splitlines():
        print(dim("    " + line))


def pause(prompt: str = "press Enter to continue") -> None:
    if UI.pause_enabled and not UI.smoke:
        try:
            input(dim(f"\n  ⏎  {prompt} "))
        except EOFError:
            pass


def ask(prompt: str, default: str = "") -> str:
    """Prompt the user; in smoke mode return the default without asking."""
    if UI.smoke:
        return default
    try:
        answer = input(yellow(f"  {prompt} ")).strip()
    except EOFError:
        return default
    return answer or default


def short(value: Any, n: int = 28) -> str:
    s = str(value)
    return s if len(s) <= n else s[:n] + "…"


# ══════════════════════════════════════════════════════════════════════════════
# Session state
# ══════════════════════════════════════════════════════════════════════════════


class Skip(Exception):
    """Flow cannot run with the current configuration."""


class Session:
    def __init__(self) -> None:
        self.client = OAuthClient(base_url=TENANT_URL) if TENANT_URL else None
        self.dpop_everywhere = False
        self.show_tokens = False
        self.authorization_details: Optional[list[dict[str, Any]]] = None
        self.extra_params: Optional[dict[str, Any]] = None
        self._dpop_key: Optional[str] = None
        # last token and how to use it again (refresh / introspection)
        self.last_token: Optional[dict[str, Any]] = None
        self.last_source = ""
        self.last_client_auth: dict[str, Any] = {}
        self.last_dpop_key: Optional[str] = None
        self.results: list[tuple[str, str, str]] = []
        self.api: Optional[ProtectedAPI] = None
        self.include_dcr = False

    @property
    def dpop_key(self) -> str:
        if self._dpop_key is None:
            self._dpop_key = OAuthClient.generate_dpop_key_pair(DPOP_KEY_TYPE)
        return self._dpop_key

    def new_dpop_key(self) -> None:
        self._dpop_key = None

    def grant_extras(self) -> dict[str, Any]:
        return {
            "authorization_details": self.authorization_details,
            "extra_params": self.extra_params,
        }

    def dpop_extras(self) -> dict[str, Any]:
        if not self.dpop_everywhere:
            return {}
        return {"dpop_private_key": self.dpop_key, "dpop_algorithm": DPOP_ALG}

    def remember(
        self,
        token: dict[str, Any],
        source: str,
        client_auth: dict[str, Any],
        dpop_key: Optional[str] = None,
    ) -> None:
        self.last_token = token
        self.last_source = source
        self.last_client_auth = client_auth
        self.last_dpop_key = dpop_key


S = Session()


def mask(token: Any) -> str:
    t = str(token or "")
    if S.show_tokens or len(t) <= 24:
        return t
    return f"{t[:12]}…{t[-6:]}" + dim(f"  ({len(t)} chars)")


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    def seg(s: str) -> dict[str, Any]:
        return dict(json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))))

    h, p, _ = token.split(".")
    return seg(h), seg(p)


def show_jwt(label: str, token: str, notes: Optional[dict[str, str]] = None) -> None:
    header, claims = decode_jwt(token)
    notes = notes or {}
    print(f"\n  {bold(label)}")
    print(magenta("  header"))
    for k, v in header.items():
        if k == "jwk" and isinstance(v, dict):
            v = {kk: short(vv, 22) for kk, vv in v.items()}
        note = dim(f"   ← {notes[k]}") if k in notes else ""
        print(f"    {k:<6} {json.dumps(v, ensure_ascii=False)}{note}")
    print(magenta("  claims"))
    for k, v in claims.items():
        shown = json.dumps(short(v, 72) if isinstance(v, str) else v, ensure_ascii=False)
        note = dim(f"   ← {notes[k]}") if k in notes else ""
        print(f"    {k:<6} {shown}{note}")


def show_token(token: dict[str, Any]) -> None:
    tt = token.get("token_type")
    kv("token_type", bold(green(tt)) if str(tt).lower() == "dpop" else tt)
    for k in ("expires_in", "scope"):
        if token.get(k) is not None:
            kv(k, token[k])
    for k in ("access_token", "refresh_token", "id_token"):
        if token.get(k):
            kv(k, mask(token[k]))
    if token.get("authorization_details"):
        kv("authorization_details", json.dumps(token["authorization_details"])[:80])
    show_claims("access token says", token.get("access_token"))
    show_claims("id token says", token.get("id_token"))


def _expires_in_words(exp: Any) -> str:
    try:
        secs = int(exp) - int(time.time())
    except (TypeError, ValueError):
        return str(exp)
    return f"in {secs // 60} min" if secs >= 0 else f"{-secs // 60} min ago"


def show_claims(label: str, token: Any) -> None:
    """Summarise the interesting claims of a JWT (access or ID token) for the audience."""
    t = str(token or "")
    if t.count(".") != 2:
        return
    try:
        _, c = decode_jwt(t)
    except Exception:
        return
    rows: list[tuple[str, Any]] = []
    for k in ("sub", "preferred_username", "name", "email", "client_id", "azp", "scope"):
        if c.get(k) not in (None, ""):
            rows.append((k, c[k]))
    if c.get("aud"):
        rows.append(("aud", short(c["aud"], 60)))
    if c.get("exp"):
        rows.append(("exp", _expires_in_words(c["exp"])))
    if c.get("act"):
        rows.append(("act", f"{c['act']}  ← delegated: acting party"))
    if c.get("cnf"):
        rows.append(("cnf", f"{c['cnf']}  ← bound to a key"))
    if c.get("authorization_details"):
        rows.append(("authorization_details", short(json.dumps(c["authorization_details"]), 60)))
    if rows:
        print(magenta(f"  {label}"))
        for k, v in rows:
            print(f"    {k:<20} {v}")


def hint(exc: VerifyError) -> None:
    text = f"{exc.error or ''} {exc.error_description or ''} {exc.message}"
    tips = {
        "CSIAQ0330E": "this app accepts only client_secret_post — pass client_secret_post=True",
        "invalid_client": "check client id/secret, or for private_key_jwt the registered key, kid and aud",
        "unauthorized_client": "enable this grant type on the application (Sign-on tab)",
        "invalid_dpop_proof": "proof alg must match the app's 'Signing algorithm for DPoP JWT'",
        "requires a DPoP proof": "this app enforces DPoP — set IBM_PKJWT_DPOP=true (or turn DPoP off on the app)",
        "use_dpop_nonce": "the tenant kept demanding a new nonce; retry once more",
        "invalid_grant": "code/refresh token expired or already used, or wrong user",
        "invalid_scope": "request only scopes enabled on the application",
        "CSIAQ5223E": "IBM_JWT_SUBJECT must be the login username, not the internal UID",
    }
    for key, tip in tips.items():
        if key in text:
            print(yellow(f"  💡 {tip}"))
            return


def need(*pairs: tuple[str, str]) -> None:
    missing = [name for name, value in pairs if not value]
    if missing:
        raise Skip("set " + ", ".join(missing) + " in .env")


def read_key(path: str) -> str:
    full = path if os.path.isabs(path) else os.path.join(HERE, path)
    if not os.path.exists(full):
        raise Skip(f"key file not found: {full}")
    with open(full) as f:
        return f.read()


def token_endpoint() -> str:
    return S.client._resolve_token_endpoint()  # type: ignore[union-attr]


# Capture the DPoP proof the SDK attaches to token requests (display only).
LAST_PROOF: dict[str, str] = {}
_original_proof_header = _sdk_base.build_token_request_dpop_header


def _recording_proof_header(*args: Any, **kwargs: Any) -> dict[str, str]:
    header = _original_proof_header(*args, **kwargs)
    LAST_PROOF["proof"] = header["DPoP"]
    return header


_sdk_base.build_token_request_dpop_header = _recording_proof_header  # type: ignore[assignment]


def show_last_proof_if_any() -> None:
    if S.dpop_everywhere and LAST_PROOF.get("proof"):
        _, claims = decode_jwt(LAST_PROOF["proof"])
        kv(
            "DPoP proof",
            f"htm={claims.get('htm')} htu={claims.get('htu')} jti={short(claims.get('jti'), 8)}",
        )


# ══════════════════════════════════════════════════════════════════════════════
# Grant flows
# ══════════════════════════════════════════════════════════════════════════════


def flow_client_credentials() -> None:
    section("Client credentials", "RFC 6749 §4.4 — service-to-service, no user")
    need(("IBM_ACTOR_CLIENT_ID", ACTOR_CLIENT_ID), ("IBM_ACTOR_CLIENT_SECRET", ACTOR_CLIENT_SECRET))
    kv("client_id", ACTOR_CLIENT_ID)
    kv("scope", ACTOR_SCOPE)
    code("client.client_credentials(client_id, client_secret, scope)")
    token = S.client.client_credentials(  # type: ignore[union-attr]
        ACTOR_CLIENT_ID,
        ACTOR_CLIENT_SECRET,
        ACTOR_SCOPE,
        **S.grant_extras(),
        **S.dpop_extras(),
    )
    show_last_proof_if_any()
    show_token(token)
    S.remember(
        token,
        "client credentials",
        {"client_id": ACTOR_CLIENT_ID, "client_secret": ACTOR_CLIENT_SECRET},
        S.dpop_key if S.dpop_everywhere else None,
    )


def flow_password() -> None:
    section("Password grant (ROPC)", "RFC 6749 §4.3 — legacy; prefer authorization code")
    need(
        ("IBM_USER_CLIENT_ID", USER_CLIENT_ID),
        ("IBM_USER_CLIENT_SECRET", USER_CLIENT_SECRET),
        ("IBM_USERNAME", USERNAME),
        ("IBM_PASSWORD", PASSWORD),
    )
    kv("client_id", USER_CLIENT_ID)
    kv("username", USERNAME)
    code("client.password_grant(client_id, client_secret, username, password, authz_header)")
    token = S.client.password_grant(  # type: ignore[union-attr]
        USER_CLIENT_ID,
        USER_CLIENT_SECRET,
        USERNAME,
        PASSWORD,
        AUTHZ_HEADER,
        scope="openid profile email",
        **S.grant_extras(),
        **S.dpop_extras(),
    )
    show_last_proof_if_any()
    show_token(token)
    S.remember(
        token,
        "password",
        {"client_id": USER_CLIENT_ID, "client_secret": USER_CLIENT_SECRET},
        S.dpop_key if S.dpop_everywhere else None,
    )


def flow_pkce() -> None:
    section("Authorization code + PKCE", "RFC 7636 — browser login, the recommended user flow")
    if UI.smoke:
        raise Skip("needs a browser login (run from the menu)")
    need(("IBM_PKCE_CLIENT_ID", PKCE_CLIENT_ID))
    parsed = urlparse(PKCE_REDIRECT_URI)
    host, port, path = (
        parsed.hostname or "localhost",
        parsed.port or 8080,
        parsed.path or "/callback",
    )

    step("1 · PKCE pair")
    verifier, challenge = OAuthClient.generate_pkce_pair()
    kv("code_verifier", short(verifier, 32) + dim("  (kept secret by the app)"))
    kv("code_challenge", short(challenge, 32) + dim("  (S256 hash, sent in the URL)"))

    step("2 · Authorization URL")
    dpop_jkt = S.client.compute_dpop_jkt(S.dpop_key) if S.dpop_everywhere else None  # type: ignore[union-attr]
    url = S.client.build_authorization_url(  # type: ignore[union-attr]
        PKCE_CLIENT_ID,
        PKCE_REDIRECT_URI,
        challenge,
        scope=PKCE_SCOPE,
        authorization_details=S.authorization_details,
        extra_params=S.extra_params,
        dpop_jkt=dpop_jkt,
    )
    print("  " + cyan(url))
    if dpop_jkt:
        say("dpop_jkt binds the authorization code to our DPoP key (RFC 9449 §10).")

    step("3 · Wait for the redirect")
    done = threading.Event()
    result: dict[str, Any] = {}

    class Callback(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            req = urlparse(self.path)
            if req.path != path:
                self.send_response(204)
                self.end_headers()
                return
            q = parse_qs(req.query)
            result["code"] = q.get("code", [None])[0]
            result["error"] = q.get("error", [None])[0]
            ok_ = bool(result["code"])
            body = (
                "<h2 style='color:#15803d'>&#10003; Signed in</h2><p>Return to the terminal.</p>"
                if ok_
                else f"<h2 style='color:#b91c1c'>&#10007; {result['error'] or 'No code'}</h2>"
            )
            page = f"<html><body style='font-family:sans-serif;text-align:center;padding:60px'>{body}</body></html>"
            self.send_response(200 if ok_ else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page.encode())
            done.set()

        def log_message(self, *args: Any) -> None:
            pass

    try:
        HTTPServer.allow_reuse_address = True
        server = HTTPServer((host, port), Callback)
    except OSError as exc:
        raise Skip(f"port {port} is busy — change IBM_PKCE_REDIRECT_URI") from exc
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ok(f"listening on {host}:{port}{path}")
    if UI.run_all or ask("Open the browser? [Y/n]", "y").lower() != "n":
        webbrowser.open(url)
    print("  ⏳ waiting up to 180 s for the login…")
    done.wait(timeout=180)
    server.shutdown()
    server.server_close()
    if not result.get("code"):
        raise VerifyError(message=f"no authorization code ({result.get('error') or 'timeout'})")
    ok(f"authorization code received: {short(result['code'], 12)}")

    step("4 · Exchange the code (with the PKCE verifier)")
    code("client.exchange_code_for_token(client_id, redirect_uri, code, code_verifier)")
    token = S.client.exchange_code_for_token(  # type: ignore[union-attr]
        PKCE_CLIENT_ID,
        PKCE_REDIRECT_URI,
        result["code"],
        verifier,
        client_secret=PKCE_CLIENT_SECRET,
        **S.grant_extras(),
        **S.dpop_extras(),
    )
    show_last_proof_if_any()
    show_token(token)
    S.remember(
        token,
        "authorization code",
        {
            "client_id": PKCE_CLIENT_ID,
            "client_secret": PKCE_CLIENT_SECRET,
            "client_secret_post": True,  # exchange_code_for_token sends the secret in the body
        },
        S.dpop_key if S.dpop_everywhere else None,
    )


def flow_device() -> None:
    section("Device authorization", "RFC 8628 — TVs, CLIs and devices without a browser")
    if UI.smoke:
        raise Skip("needs approval on a second device (run from the menu)")
    need(("IBM_DEVICE_CLIENT_ID", DEVICE_CLIENT_ID))
    data = S.client.request_device_code(  # type: ignore[union-attr]
        DEVICE_CLIENT_ID, DEVICE_SCOPE, client_secret=DEVICE_CLIENT_SECRET, **S.grant_extras()
    )
    uri = data.get("verification_uri_complete") or data.get("verification_uri")
    print()
    kv("open", cyan(uri))
    kv("enter code", bold(green(data.get("user_code"))))
    kv("expires in", f"{data.get('expires_in')} s")
    if UI.run_all or ask("Open the browser? [Y/n]", "y").lower() != "n":
        webbrowser.open(str(uri))
    stop = threading.Event()

    def ticker() -> None:
        t = 0
        while not stop.wait(1):
            t += 1
            print(f"\r  ⏳ polling… {t}s ", end="", flush=True)

    threading.Thread(target=ticker, daemon=True).start()
    try:
        token = S.client.poll_device_token(  # type: ignore[union-attr]
            DEVICE_CLIENT_ID,
            data["device_code"],
            interval=data.get("interval", 5),
            expires_in=data.get("expires_in", 300),
            client_secret=DEVICE_CLIENT_SECRET,
            extra_params=S.extra_params,
            **S.dpop_extras(),
        )
    finally:
        stop.set()
        print()
    show_token(token)
    S.remember(
        token,
        "device code",
        {
            "client_id": DEVICE_CLIENT_ID,
            "client_secret": DEVICE_CLIENT_SECRET,
            "client_secret_post": True,  # IBM Verify device clients accept only client_secret_post
        },
        S.dpop_key if S.dpop_everywhere else None,
    )


def flow_refresh() -> None:
    section("Refresh token", "RFC 6749 §6 — new access token without the user")
    if not (S.last_token or {}).get("refresh_token"):
        say("No refresh token yet — getting one with the password grant first.")
        flow_password()
    if not (S.last_token or {}).get("refresh_token"):
        raise Skip("the last token has no refresh_token (enable the refresh grant on the app)")
    auth = S.last_client_auth
    kv("from", S.last_source)
    kv("client_id", auth.get("client_id"))
    kv("refresh_token", mask(S.last_token["refresh_token"]))  # type: ignore[index]
    if S.last_dpop_key:
        say("The token is DPoP-bound, so the refresh must be signed with the same key.")
    code(
        "client.refresh_access_token(client_id, refresh_token, client_secret"
        + (", client_secret_post=True)" if auth.get("client_secret_post") else ")")
    )
    token = S.client.refresh_access_token(  # type: ignore[union-attr]
        auth["client_id"],
        S.last_token["refresh_token"],  # type: ignore[index]
        client_secret=auth.get("client_secret"),
        client_assertion=auth.get("client_assertion"),
        client_secret_post=bool(auth.get("client_secret_post")),
        dpop_private_key=S.last_dpop_key,
        dpop_algorithm=DPOP_ALG,
        **S.grant_extras(),
    )
    show_token(token)
    rotated = token.get("refresh_token") and token.get("refresh_token") != S.last_token.get("refresh_token")  # type: ignore[union-attr]
    kv("refresh rotated", "yes" if rotated else "no")
    S.remember(token, "refresh", auth, S.last_dpop_key)


def flow_exchange() -> None:
    section("Token exchange", "RFC 8693 — a service acts on behalf of the user")
    need(
        ("IBM_EXCHANGE_CLIENT_ID", EXCHANGE_CLIENT_ID),
        ("IBM_EXCHANGE_CLIENT_SECRET", EXCHANGE_CLIENT_SECRET),
        ("IBM_ACTOR_CLIENT_ID", ACTOR_CLIENT_ID),
        ("IBM_ACTOR_CLIENT_SECRET", ACTOR_CLIENT_SECRET),
        ("IBM_USER_CLIENT_ID", USER_CLIENT_ID),
        ("IBM_USER_CLIENT_SECRET", USER_CLIENT_SECRET),
        ("IBM_USERNAME", USERNAME),
        ("IBM_PASSWORD", PASSWORD),
    )
    step("1 · Subject token — the user (password grant)")
    subject = S.client.password_grant(  # type: ignore[union-attr]
        USER_CLIENT_ID, USER_CLIENT_SECRET, USERNAME, PASSWORD, AUTHZ_HEADER, scope="openid"
    )
    kv("subject_token", mask(subject["access_token"]))
    step("2 · Actor token — the calling service (client credentials)")
    actor = S.client.client_credentials(  # type: ignore[union-attr]
        ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET, ACTOR_SCOPE
    )
    kv("actor_token", mask(actor["access_token"]))
    step("3 · Exchange")
    code("client.token_exchange(client_id, client_secret, subject_token, actor_token)")
    token = S.client.token_exchange(  # type: ignore[union-attr]
        EXCHANGE_CLIENT_ID,
        EXCHANGE_CLIENT_SECRET,
        subject["access_token"],
        actor["access_token"],
        **S.grant_extras(),
        **S.dpop_extras(),
    )
    show_last_proof_if_any()
    show_token(token)
    S.remember(
        token,
        "token exchange",
        {"client_id": EXCHANGE_CLIENT_ID, "client_secret": EXCHANGE_CLIENT_SECRET},
        S.dpop_key if S.dpop_everywhere else None,
    )


def flow_jwt_bearer() -> None:
    section("JWT bearer grant", "RFC 7523 §2.1 — a trusted issuer's signed JWT becomes a token")
    need(
        ("IBM_JWT_CLIENT_ID", JWT_CLIENT_ID),
        ("IBM_JWT_KID", JWT_KID),
        ("IBM_JWT_SUBJECT", JWT_SUBJECT),
    )
    key = read_key(JWT_PRIVATE_KEY_PATH)
    endpoint = token_endpoint()
    assertion = OAuthClient.generate_jwt_bearer_assertion(
        subject=JWT_SUBJECT,
        token_endpoint=endpoint,
        issuer=JWT_ISSUER,
        private_key=key,
        key_id=JWT_KID,
    )
    show_jwt(
        "assertion",
        assertion,
        {
            "kid": "certificate label in Security → Certificates",
            "sub": "the IBM Verify user",
            "aud": "token endpoint",
        },
    )
    code("client.jwt_bearer_grant(assertion, client_id=..., client_secret=...)")
    token = S.client.jwt_bearer_grant(  # type: ignore[union-attr]
        assertion,
        client_id=JWT_CLIENT_ID,
        client_secret=JWT_CLIENT_SECRET,
        scope="openid",
        **S.grant_extras(),
        **S.dpop_extras(),
    )
    show_last_proof_if_any()
    show_token(token)
    S.remember(
        token,
        "jwt bearer",
        {"client_id": JWT_CLIENT_ID, "client_secret": JWT_CLIENT_SECRET},
        S.dpop_key if S.dpop_everywhere else None,
    )


# ══════════════════════════════════════════════════════════════════════════════
# DPoP showcase — with a local protected API that validates via the SDK
# ══════════════════════════════════════════════════════════════════════════════


class ProtectedAPI:
    """A tiny DPoP-only API on 127.0.0.1 that validates with introspect_dpop_token()."""

    def __init__(self, port: int, client_id: str, client_secret: str) -> None:
        self.base = f"http://127.0.0.1:{port}"
        self.replay_cache = InMemoryDPoPReplayCache()
        rs = OAuthClient(base_url=TENANT_URL)
        api = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                url = api.base + self.path
                auth = self.headers.get("Authorization", "")
                proof = self.headers.get("DPoP")
                if not auth.startswith("DPoP ") or not proof:
                    return self._reply(401, "DPoP token and proof required (Bearer not accepted)")
                try:
                    info = rs.introspect_dpop_token(
                        auth[5:],
                        proof,
                        self.command,
                        url,
                        replay_cache=api.replay_cache,
                        client_id=client_id,
                        client_secret=client_secret,
                    )
                except VerifyError as exc:
                    return self._reply(401, exc.error_description or exc.message)
                if not info.get("active"):
                    return self._reply(401, "token is not active")
                self._reply(
                    200, "proof valid, key bound to token", {"photos": ["beach.jpg", "hills.jpg"]}
                )

            def _reply(
                self, status: int, reason: str, body: Optional[dict[str, Any]] = None
            ) -> None:
                colour = green if status == 200 else red
                sys.stdout.write(
                    colour(f"      [API] {status}  {self.command} {self.path}  — {reason}") + "\n"
                )
                sys.stdout.flush()
                data = json.dumps(body or {"error": "invalid_token", "reason": reason}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if status == 401:
                    self.send_header("WWW-Authenticate", 'DPoP error="invalid_token"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _handle
            do_POST = _handle

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _proof(key: str, htm: str, htu: str, token: str, iat_offset: int = 0) -> str:
    k = JsonWebKey.import_key(key)
    alg = DPOP_ALG or ("RS256" if k.as_dict().get("kty") == "RSA" else "ES256")
    claims = {
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()) + iat_offset,
        "htm": htm,
        "htu": htu,
        "ath": compute_ath(token),
    }
    t = authlib_jwt.encode({"typ": "dpop+jwt", "alg": alg, "jwk": _public_jwk(k)}, claims, k)
    return t.decode() if isinstance(t, bytes) else t


def _attack(label: str, method: str, url: str, headers: dict[str, str]) -> bool:
    print(f"\n  {bold(label)}")
    r = httpx.request(method, url, headers=headers, timeout=30, trust_env=False)
    if r.status_code == 401:
        ok(f"rejected — {r.json().get('reason')}")
        return True
    fail(f"ACCEPTED with HTTP {r.status_code}")
    return False


def flow_dpop() -> None:
    section("DPoP — Demonstrating Proof of Possession", "RFC 9449 — a stolen token is useless")
    need(("IBM_DPOP_CLIENT_ID", DPOP_CLIENT_ID), ("IBM_DPOP_CLIENT_SECRET", DPOP_CLIENT_SECRET))
    c = S.client
    assert c is not None
    say(
        "A bearer token works for whoever holds it. DPoP binds the token to a key pair "
        "only the client holds; every request must carry a fresh proof signed with it."
    )
    pause()

    step("1 · Tenant capabilities")
    md = c.get_discovery()
    kv("token endpoint", md.get("token_endpoint"))
    kv("DPoP algorithms", md.get("dpop_signing_alg_values_supported", "n/a"))
    say("The application has 'Enforce DPoP-bound access token' enabled.")
    pause()

    step("2 · The client's key pair")
    key = OAuthClient.generate_dpop_key_pair(DPOP_KEY_TYPE)
    jkt = c.compute_dpop_jkt(key)
    kv("public key", {k: short(v, 18) for k, v in _public_jwk(JsonWebKey.import_key(key)).items()})
    kv("thumbprint (jkt)", bold(jkt))
    say("The private key never leaves this process.")
    pause()

    step("3 · Token request with a DPoP proof")
    code("client.client_credentials(client_id, client_secret, scope, dpop_private_key=key)")
    token = c.client_credentials(
        DPOP_CLIENT_ID,
        DPOP_CLIENT_SECRET,
        DPOP_SCOPE,
        dpop_private_key=key,
        dpop_algorithm=DPOP_ALG,
    )
    show_jwt(
        "proof sent in the DPoP header",
        LAST_PROOF["proof"],
        {
            "typ": "this JWT is a DPoP proof",
            "jwk": "the client's PUBLIC key",
            "jti": "unique — single use",
            "iat": "created now",
            "htm": "only for this method",
            "htu": "only for this URL",
            "nonce": "server nonce (handled automatically)",
        },
    )
    print()
    show_token(token)
    S.remember(
        token,
        "DPoP client credentials",
        {"client_id": DPOP_CLIENT_ID, "client_secret": DPOP_CLIENT_SECRET},
        key,
    )
    pause()

    step("4 · Introspection — token bound to our key")
    info = c.introspect_token(
        token["access_token"], client_id=DPOP_CLIENT_ID, client_secret=DPOP_CLIENT_SECRET
    )
    server_jkt = (info.get("cnf") or {}).get("jkt")
    kv("cnf.jkt (IBM Verify)", bold(server_jkt))
    kv("jkt (our key)", bold(jkt))
    (ok if server_jkt == jkt else fail)(
        "thumbprints match" if server_jkt == jkt else "thumbprints differ"
    )
    pause()

    step("5 · Call a protected API")
    if S.api is None:
        try:
            S.api = ProtectedAPI(API_PORT, DPOP_CLIENT_ID, DPOP_CLIENT_SECRET)
        except OSError as exc:
            raise Skip(f"port {API_PORT} is busy — set IBM_DEMO_API_PORT") from exc
    photos, transfer = f"{S.api.base}/photos", f"{S.api.base}/transfer"
    say(
        f"A sample API is running at {S.api.base}; it accepts only DPoP tokens and checks every proof."
    )
    code('client.dpop_request("GET", url, access_token, private_key)')
    r = c.dpop_request("GET", photos, token["access_token"], key, algorithm=DPOP_ALG)
    sent = r.request.headers["DPoP"]
    show_jwt(
        "proof for the API call", sent, {"htu": "this API URL", "ath": "hash of THIS access token"}
    )
    print()
    kv("API response", f"{r.status_code} {r.text[:50]}")
    if r.status_code != 200:
        raise VerifyError(message=f"protected API returned {r.status_code}")
    ok("legitimate client → access granted")
    pause()

    step("6 · An attacker stole the token and one proof")
    pause("press Enter to run the attacks")
    stolen, evil = token["access_token"], OAuthClient.generate_dpop_key_pair(DPOP_KEY_TYPE)
    results = [
        _attack(
            "A. Stolen token as a plain Bearer token",
            "GET",
            photos,
            {"Authorization": f"Bearer {stolen}"},
        ),
        _attack(
            "B. Fresh proof signed with the attacker's key",
            "GET",
            photos,
            {"Authorization": f"DPoP {stolen}", "DPoP": _proof(evil, "GET", photos, stolen)},
        ),
        _attack(
            "C. Replay the captured proof",
            "GET",
            photos,
            {"Authorization": f"DPoP {stolen}", "DPoP": sent},
        ),
        _attack(
            "D. Captured proof on another endpoint (POST /transfer)",
            "POST",
            transfer,
            {"Authorization": f"DPoP {stolen}", "DPoP": sent},
        ),
        _attack(
            "E. Genuine proof captured 10 minutes ago",
            "GET",
            photos,
            {"Authorization": f"DPoP {stolen}", "DPoP": _proof(key, "GET", photos, stolen, -600)},
        ),
    ]
    step("Summary")
    for (label, expect), passed in zip(
        [
            ("Stolen token as Bearer", "401"),
            ("Attacker's own key", "thumbprint ≠ cnf.jkt"),
            ("Replayed proof", "jti already used"),
            ("Proof on another endpoint", "htm/htu mismatch"),
            ("Stale proof", "iat too old"),
        ],
        results,
    ):
        print(f"  {green('✔') if passed else red('✘')} {label:<28} {dim(expect)}")
    if not all(results):
        raise VerifyError(message="an attack was not rejected")


# ══════════════════════════════════════════════════════════════════════════════
# private_key_jwt showcase
# ══════════════════════════════════════════════════════════════════════════════


def _pkjwt_setup() -> tuple[str, str, Callable[..., str]]:
    need(("IBM_PKJWT_CLIENT_ID", PKJWT_CLIENT_ID), ("IBM_PKJWT_PRIVATE_KEY_PATH", PKJWT_KEY_PATH))
    key = read_key(PKJWT_KEY_PATH)
    endpoint = token_endpoint()

    def make(
        token_endpoint: Optional[str] = None, private_key: Optional[str] = None, **kw: Any
    ) -> str:
        """A fresh assertion (new jti) each call; overrides are used by the attack demos."""
        kw.setdefault("algorithm", PKJWT_ALG)
        kw.setdefault("key_id", PKJWT_KID)
        return OAuthClient.generate_client_assertion_jwt(
            PKJWT_CLIENT_ID, token_endpoint or endpoint, private_key or key, **kw
        )

    return key, endpoint, make


def flow_pkjwt() -> None:
    section("private_key_jwt client authentication", "RFC 7523 §2.2 — no shared secret")
    key, endpoint, make = _pkjwt_setup()
    c = S.client
    assert c is not None
    say(
        "A client secret is a shared password that can leak from config, logs or CI. "
        "With private_key_jwt the app proves who it is with a short-lived JWT signed by "
        "its own private key; IBM Verify stores only the public key."
    )
    pause()

    step("1 · Tenant capabilities")
    md = c.get_discovery()
    kv("auth methods", md.get("token_endpoint_auth_methods_supported"))
    kv("assertion algs", md.get("token_endpoint_auth_signing_alg_values_supported"))
    pause()

    step("2 · Build the client assertion")
    code("client.generate_client_assertion_jwt(client_id, token_endpoint, private_key, key_id=kid)")
    assertion = make()
    show_jwt(
        "client_assertion",
        assertion,
        {
            "alg": "signed with the client's private key",
            "kid": "which registered key to use",
            "iss": "the client…",
            "sub": "…asserting its own identity",
            "aud": "only valid at this token endpoint",
            "jti": "unique — single use",
            "exp": "valid for 5 minutes",
        },
    )
    pause()

    step("3 · Token request — no secret on the wire")
    for k, v in {
        "grant_type": "client_credentials",
        "client_id": PKJWT_CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": short(assertion, 30),
    }.items():
        kv(k, v, 24)
    print(dim("    (no client_secret, no Authorization header)"))
    # If the app also enforces DPoP (IBM_PKJWT_DPOP=true), every token request
    # must carry a DPoP proof as well — otherwise IBM Verify answers CSIAQ5168E.
    dpop: dict[str, Any] = (
        {"dpop_private_key": S.dpop_key, "dpop_algorithm": DPOP_ALG} if PKJWT_DPOP else {}
    )
    if dpop:
        print(dim("    + DPoP proof header (this app enforces DPoP-bound tokens)"))
    first = [assertion]

    def step3_assertion() -> str:
        # The assertion shown above; a fresh one if a DPoP-nonce retry happens.
        return first.pop() if first else make()

    token = c.client_credentials(
        PKJWT_CLIENT_ID,
        scope=PKJWT_SCOPE,
        client_assertion=step3_assertion,
        **S.grant_extras(),
        **dpop,
    )
    show_token(token)
    S.remember(
        token,
        "private_key_jwt",
        {"client_id": PKJWT_CLIENT_ID, "client_assertion": lambda: make()},
        S.dpop_key if dpop else None,
    )
    pause()

    step("4 · Introspection, also with private_key_jwt")
    info = c.introspect_token(
        token["access_token"], client_id=PKJWT_CLIENT_ID, client_assertion=lambda: make()
    )
    for k in ("active", "client_id", "scope"):
        kv(k, info.get(k))
    pause()

    step("5 · Attacks IBM Verify must reject")
    say("The attacker knows the client_id and has seen one assertion on the wire.")
    pause("press Enter to run the attacks")
    evil_key = OAuthClient.generate_dpop_key_pair("RSA")
    h, p, sig = assertion.split(".")
    claims = decode_jwt(assertion)[1]
    forged_payload = (
        base64.urlsafe_b64encode(
            json.dumps({**claims, "exp": claims["exp"] + 86400}, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    def attempt(label: str, a: str) -> Optional[bool]:
        print(f"\n  {bold(label)}")
        try:
            c.client_credentials(  # type: ignore[union-attr]
                PKJWT_CLIENT_ID, scope=PKJWT_SCOPE, client_assertion=a, **dpop
            )
        except VerifyError as exc:
            if "DPoP" in str(exc.error_description):
                warn(
                    f"inconclusive — rejected for a DPoP reason: {short(exc.error_description, 60)}"
                )
                return None
            ok(f"rejected — {exc.error}: {short(exc.error_description, 70)}")
            return True
        return False

    rows: list[tuple[str, Optional[bool], str]] = [
        (
            "A. Signed with the attacker's key",
            attempt("A. Signed with the attacker's key", make(private_key=evil_key)),
            "signature ≠ registered key",
        ),
        (
            "B. Tampered claims (exp +1 day)",
            attempt("B. Tampered claims (exp +1 day)", f"{h}.{forged_payload}.{sig}"),
            "signature no longer matches",
        ),
        (
            "C. Wrong audience",
            attempt("C. Wrong audience", make(token_endpoint="https://evil.example.com/token")),
            "aud ≠ token endpoint",
        ),
        (
            "D. Expired assertion",
            attempt("D. Expired assertion", make(expires_in=-60)),
            "exp in the past",
        ),
    ]
    for label, passed, _ in rows:
        if passed is False:
            fail(f"{label}: ACCEPTED")
    print(f"\n  {bold('E. Replay the assertion from step 3')}")
    try:
        c.client_credentials(PKJWT_CLIENT_ID, scope=PKJWT_SCOPE, client_assertion=assertion, **dpop)
        warn(
            "accepted — this tenant does not track assertion jti; the 5-minute exp limits the window"
        )
        rows.append(("E. Replayed assertion", None, "accepted within exp window"))
    except VerifyError as exc:
        ok(f"rejected — {exc.error}: {short(exc.error_description, 70)}")
        rows.append(("E. Replayed assertion", True, "jti already used"))

    step("Summary")
    for label, passed, expect in rows:
        mark = green("✔") if passed else (yellow("•") if passed is None else red("✘"))
        print(f"  {mark} {label:<34} {dim(expect)}")
    if any(p is False for _, p, _ in rows):
        raise VerifyError(message="an attack was not rejected")


def flow_pkjwt_dpop() -> None:
    section("private_key_jwt + DPoP", "who the client is  +  who may use the token")
    _, _, make = _pkjwt_setup()
    c = S.client
    assert c is not None
    if not PKJWT_DPOP:
        warn("IBM_PKJWT_DPOP is not 'true' — the app may not enforce DPoP; the token may be Bearer")
    key = OAuthClient.generate_dpop_key_pair(DPOP_KEY_TYPE)
    code("""
client.client_credentials(
    client_id, scope,
    client_assertion=lambda: generate_client_assertion_jwt(...),  # fresh per attempt
    dpop_private_key=key,
)""")
    say("A callable assertion lets the SDK's automatic DPoP-nonce retry send a fresh assertion.")
    token = c.client_credentials(
        PKJWT_CLIENT_ID,
        scope=PKJWT_SCOPE,
        client_assertion=lambda: make(),
        dpop_private_key=key,
        dpop_algorithm=DPOP_ALG,
    )
    if LAST_PROOF.get("proof"):
        show_jwt("DPoP proof on the same request", LAST_PROOF["proof"])
    print()
    show_token(token)
    info = c.introspect_token(
        token["access_token"], client_id=PKJWT_CLIENT_ID, client_assertion=lambda: make()
    )
    jkt = c.compute_dpop_jkt(key)
    kv("cnf.jkt", (info.get("cnf") or {}).get("jkt"))
    kv("our jkt", jkt)
    bound = (info.get("cnf") or {}).get("jkt") == jkt
    (ok if bound else warn)(
        "token is bound to the DPoP key" if bound else "token is not DPoP-bound"
    )
    S.remember(
        token,
        "private_key_jwt + DPoP",
        {"client_id": PKJWT_CLIENT_ID, "client_assertion": lambda: make()},
        key,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Tokens & metadata
# ══════════════════════════════════════════════════════════════════════════════


def flow_introspect() -> None:
    section("Token introspection", "RFC 7662 — is this token active, and what is it bound to?")
    if not S.last_token:
        say("No token yet — running client credentials first.")
        flow_client_credentials()
    auth = S.last_client_auth
    kv("token from", S.last_source)
    kv("introspect as", auth.get("client_id"))
    info = S.client.introspect_token(  # type: ignore[union-attr]
        S.last_token["access_token"],  # type: ignore[index]
        client_id=auth.get("client_id"),
        client_secret=auth.get("client_secret"),
        client_assertion=auth.get("client_assertion"),
        token_type_hint="access_token",
    )
    for k in (
        "active",
        "token_type",
        "client_id",
        "sub",
        "scope",
        "exp",
        "cnf",
        "authorization_details",
    ):
        if info.get(k) is not None:
            kv(k, info[k])
    if S.last_dpop_key and info.get("cnf"):
        match = info["cnf"].get("jkt") == S.client.compute_dpop_jkt(S.last_dpop_key)  # type: ignore[union-attr]
        (ok if match else fail)(
            "cnf.jkt matches our DPoP key" if match else "cnf.jkt does not match"
        )
    if not info.get("active"):
        raise VerifyError(message="token is not active")


def flow_discovery() -> None:
    section("OIDC discovery", "what this tenant supports")
    md = S.client.load_discovery(op_name=OP_NAME)  # type: ignore[union-attr]
    for k in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "introspection_endpoint",
        "device_authorization_endpoint",
        "registration_endpoint",
        "jwks_uri",
    ):
        if md.get(k):
            kv(k.replace("_endpoint", ""), md.get(k), 22)
    print()
    for k, label in (
        ("grant_types_supported", "grant types"),
        ("token_endpoint_auth_methods_supported", "client auth"),
        ("dpop_signing_alg_values_supported", "DPoP algs"),
        ("authorization_details_types_supported", "RAR types"),
    ):
        if md.get(k):
            kv(label, md.get(k), 16)
    if not UI.tour and ask("Show the full document? [y/N]", "n").lower() == "y":
        print(json.dumps(dict(md), indent=2))


def flow_jwks() -> None:
    section("JWKS", "the tenant's public signing keys")
    jwks = S.client.get_jwks(op_name=OP_NAME)  # type: ignore[union-attr]
    keys = jwks.get("keys", [])
    ok(f"{len(keys)} key(s)")
    for k in keys:
        details = "  ".join(
            f"{name}={k[name]}" for name in ("kty", "alg", "use", "crv") if k.get(name)
        )
        kv(str(k.get("kid")), details, 30)


def flow_dcr() -> None:
    section(
        "Dynamic client registration", "RFC 7591 / 7592 — create, read, update, delete a client"
    )
    if not (DCR_INITIAL_ACCESS_TOKEN or (CLIENT_ID and CLIENT_SECRET)):
        raise Skip(
            "set IBM_DCR_INITIAL_ACCESS_TOKEN, or IBM_CLIENT_ID/IBM_CLIENT_SECRET (API client)"
        )
    if UI.smoke and not S.include_dcr:
        raise Skip("creates a client on the tenant — add --include-dcr")
    if (
        not UI.smoke
        and not S.include_dcr
        and ask("This creates a temporary client and deletes it. Continue? [y/N]", "n").lower()
        != "y"
    ):
        raise Skip("cancelled")
    c = S.client
    assert c is not None
    meta = {
        "client_name": f"verify-sdk-demo-{uuid.uuid4().hex[:6]}",
        "grant_types": ["client_credentials"],
        "response_types": ["token"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "openid",
    }
    iat = DCR_INITIAL_ACCESS_TOKEN
    if not iat:
        step("0 · Initial access token from the API client (client credentials)")
        iat = c.client_credentials(CLIENT_ID, CLIENT_SECRET, "openid")["access_token"]
        kv("API client", CLIENT_ID)
        kv("access token", mask(iat))
    step("1 · Register")
    reg = c.register_client(meta, initial_access_token=iat)
    rat, rcu = reg["registration_access_token"], reg["registration_client_uri"]
    kv("client_id", reg.get("client_id"))
    kv("client_secret", mask(reg.get("client_secret")))
    step("2 · Read")
    info = c.read_client(rat, rcu)
    kv("client_name", info.get("client_name"))
    step("3 · Update")
    body = {
        k: v
        for k, v in info.items()
        if k
        not in (
            "client_id",
            "client_secret",
            "client_id_issued_at",
            "client_secret_expires_at",
            "registration_access_token",
            "registration_client_uri",
        )
    }
    body["client_name"] = meta["client_name"] + "-updated"
    updated = c.update_client(info.get("registration_access_token", rat), rcu, body)
    kv("client_name", updated.get("client_name"))
    step("4 · Delete")
    c.delete_client(updated.get("registration_access_token", rat), rcu)
    ok("client deleted")


# ══════════════════════════════════════════════════════════════════════════════
# Settings, runner, menu
# ══════════════════════════════════════════════════════════════════════════════

RAR_PRESETS: dict[str, list[dict[str, Any]]] = {
    "1": [
        {"type": "payment_initiation", "instructedAmount": {"currency": "USD", "amount": "100.00"}}
    ],
    "2": [{"type": "account_information", "access": {"accounts": ["read"], "balances": ["read"]}}],
}


def settings() -> None:
    while True:
        section("Settings")
        print(f"  1  DPoP on every grant          [{green('on') if S.dpop_everywhere else 'off'}]")
        print(f"  2  Show full tokens             [{yellow('on') if S.show_tokens else 'off'}]")
        print(
            f"  3  authorization_details (RAR)  [{json.dumps(S.authorization_details)[:40] if S.authorization_details else 'none'}]"
        )
        print(
            f"  4  extra_params                 [{json.dumps(S.extra_params)[:40] if S.extra_params else 'none'}]"
        )
        print("  5  New DPoP key for this session")
        print("  0  Back")
        choice = ask("Choice:", "0")
        if choice == "1":
            S.dpop_everywhere = not S.dpop_everywhere
            if S.dpop_everywhere:
                ok(f"DPoP on — every grant now sends a proof (jkt {short(S.client.compute_dpop_jkt(S.dpop_key), 16)})")  # type: ignore[union-attr]
        elif choice == "2":
            S.show_tokens = not S.show_tokens
        elif choice == "3":
            print("  1 payment_initiation   2 account_information   3 custom JSON   0 clear")
            sub = ask("RAR:", "")
            if sub in RAR_PRESETS:
                S.authorization_details = RAR_PRESETS[sub]
            elif sub == "3":
                try:
                    v = json.loads(ask("JSON array:", "[]"))
                    S.authorization_details = v if isinstance(v, list) else [v]
                except json.JSONDecodeError as exc:
                    fail(f"invalid JSON: {exc}")
            elif sub == "0":
                S.authorization_details = None
        elif choice == "4":
            raw = ask(
                'JSON object, e.g. {"resource": "https://api.example.com"} (empty clears):', ""
            )
            try:
                S.extra_params = json.loads(raw) if raw else None
            except json.JSONDecodeError as exc:
                fail(f"invalid JSON: {exc}")
        elif choice == "5":
            S.new_dpop_key()
            ok(f"new key, jkt {short(S.client.compute_dpop_jkt(S.dpop_key), 16)}")  # type: ignore[union-attr]
        else:
            return


FLOWS: dict[str, tuple[str, Callable[[], None], bool]] = {
    # name: (label, function, runs unattended in --smoke)
    "discovery": ("OIDC discovery", flow_discovery, True),
    "jwks": ("JWKS", flow_jwks, True),
    "cc": ("Client credentials", flow_client_credentials, True),
    "password": ("Password (ROPC)", flow_password, True),
    "refresh": ("Refresh token", flow_refresh, True),
    "exchange": ("Token exchange", flow_exchange, True),
    "jwt-bearer": ("JWT bearer grant", flow_jwt_bearer, True),
    "introspect": ("Introspect last token", flow_introspect, True),
    "dpop": ("DPoP", flow_dpop, True),
    "pkjwt": ("private_key_jwt", flow_pkjwt, True),
    "pkjwt-dpop": ("private_key_jwt + DPoP", flow_pkjwt_dpop, True),
    "dcr": ("Dynamic client registration", flow_dcr, True),
    "pkce": ("Authorization code + PKCE", flow_pkce, False),
    "device": ("Device authorization", flow_device, False),
}

# What each flow is and when to use it — shown under the flow's title.
STORY: dict[str, tuple[str, str]] = {
    "discovery": (
        "The tenant publishes its endpoints and capabilities at a well-known URL.",
        "Always first: the SDK resolves every endpoint from it — no hard-coded URLs.",
    ),
    "jwks": (
        "The public keys IBM Verify signs tokens with.",
        "APIs use them to validate JWT access tokens and ID tokens offline.",
    ),
    "cc": (
        "The application authenticates as itself; there is no user.",
        "Back-end services, batch jobs and service-to-service APIs.",
    ),
    "password": (
        "The app collects the user's username and password and sends them to IBM Verify.",
        "Only trusted first-party or legacy apps; removed in OAuth 2.1 — prefer PKCE.",
    ),
    "pkce": (
        "The user signs in on IBM Verify's page; the app gets a one-time code and proves "
        "it started the login with the PKCE verifier.",
        "Every app with a user: web, single-page, mobile and desktop.",
    ),
    "device": (
        "The device shows a short code; the user approves on a phone or laptop while the device polls.",
        "TVs, CLIs and IoT — anything without a usable browser or keyboard.",
    ),
    "refresh": (
        "Trade a refresh token for a new access token without involving the user.",
        "Long sessions with short-lived access tokens; IBM Verify rotates the refresh token.",
    ),
    "exchange": (
        "A service trades the user's token plus its own for a new token that records the delegation.",
        "Microservice chains that call downstream APIs on behalf of the user.",
    ),
    "jwt-bearer": (
        "A trusted system signs a JWT about a user; IBM Verify checks it with a registered "
        "certificate and issues a token for that user.",
        "Federation and back-end systems that have already authenticated the user.",
    ),
    "introspect": (
        "Ask IBM Verify whether a token is active and what it carries.",
        "APIs receiving opaque tokens, or checking revocation and key binding.",
    ),
    "dpop": (
        "Bind the access token to a key only the client holds; each request carries a fresh signed proof.",
        "Public clients, mobile/SPA, high-value APIs, FAPI 2.0 — where a stolen token must be useless.",
    ),
    "pkjwt": (
        "The client authenticates with a short-lived JWT signed by its private key — no shared secret.",
        "Confidential clients, regulated environments (FAPI), anywhere secrets leak or rotate badly.",
    ),
    "pkjwt-dpop": (
        "private_key_jwt proves who the client is; DPoP decides who can use the token.",
        "The strongest combination for sensitive APIs.",
    ),
    "dcr": (
        "Applications register themselves through an API instead of the admin console.",
        "Onboarding at scale, partner portals and automated test environments.",
    ),
}


def _file_exists(path: str) -> bool:
    return bool(path) and os.path.exists(path if os.path.isabs(path) else os.path.join(HERE, path))


def ready(name: str) -> bool:
    """True if .env has what this flow needs (used for the menu and the tour)."""
    checks: dict[str, bool] = {
        "discovery": True,
        "jwks": True,
        "introspect": True,
        "cc": bool(ACTOR_CLIENT_ID and ACTOR_CLIENT_SECRET),
        "password": bool(USER_CLIENT_ID and USER_CLIENT_SECRET and USERNAME and PASSWORD),
        "refresh": bool(USER_CLIENT_ID and USER_CLIENT_SECRET and USERNAME and PASSWORD),
        "exchange": bool(
            EXCHANGE_CLIENT_ID and EXCHANGE_CLIENT_SECRET and ACTOR_CLIENT_ID and USERNAME
        ),
        "jwt-bearer": bool(JWT_CLIENT_ID and JWT_KID and _file_exists(JWT_PRIVATE_KEY_PATH)),
        "pkce": bool(PKCE_CLIENT_ID),
        "device": bool(DEVICE_CLIENT_ID),
        "dpop": bool(DPOP_CLIENT_ID and DPOP_CLIENT_SECRET),
        "pkjwt": bool(PKJWT_CLIENT_ID and _file_exists(PKJWT_KEY_PATH)),
        "pkjwt-dpop": bool(PKJWT_CLIENT_ID and _file_exists(PKJWT_KEY_PATH)),
        "dcr": bool(DCR_INITIAL_ACCESS_TOKEN or (CLIENT_ID and CLIENT_SECRET)),
    }
    return checks.get(name, True)


def run_flow(name: str) -> str:
    label, fn, _ = FLOWS[name]
    LAST_PROOF.clear()
    _pending_story.clear()
    if name in STORY:
        _pending_story.append(STORY[name])
    try:
        fn()
        status, note = "PASS", ""
    except Skip as exc:
        status, note = "SKIP", str(exc)
        warn(f"skipped — {exc}")
    except VerifyError as exc:
        status, note = "FAIL", short(exc.error_description or exc.message or exc.error, 60)
        fail(f"{label} failed: {exc}")
        hint(exc)
    except Exception as exc:  # noqa: BLE001 — keep the menu alive for any sample error
        status, note = "FAIL", short(f"{type(exc).__name__}: {exc}", 60)
        fail(f"{label} failed: {type(exc).__name__}: {exc}")
    finally:
        _pending_story.clear()
    S.results.append((label, status, note))
    return status


def scoreboard(title: str) -> dict[str, int]:
    section(title)
    for label, status, note in S.results:
        badge = {"PASS": green("✔ PASS"), "FAIL": red("✘ FAIL"), "SKIP": dim("· SKIP")}[status]
        print(f"  {badge}  {label:<30} {dim(note)}")
    counts = {s_: sum(1 for _, st, _ in S.results if st == s_) for s_ in ("PASS", "FAIL", "SKIP")}
    print(
        f"\n  {green(counts['PASS'])} passed · {red(counts['FAIL'])} failed · "
        f"{dim(counts['SKIP'])} skipped"
    )
    return counts


def smoke(include_dcr: bool) -> int:
    UI.smoke = True
    S.include_dcr = include_dcr
    section("Smoke test — every non-interactive flow", TENANT_URL)
    for name in (
        "discovery",
        "jwks",
        "cc",
        "password",
        "refresh",
        "exchange",
        "jwt-bearer",
        "introspect",
        "dpop",
        "pkjwt",
        "pkjwt-dpop",
        "dcr",
    ):
        run_flow(name)
    counts = scoreboard("Results")
    print(
        dim("  Interactive flows to run from the menu: 3 (authorization code + PKCE), 4 (device).")
    )
    return 1 if counts["FAIL"] else 0


# The guided tour: the story told in five chapters.
TOUR: list[tuple[str, str, list[str]]] = [
    ("1", "Know your tenant", ["discovery", "jwks"]),
    (
        "2",
        "Getting tokens — the OAuth 2.0 grants",
        ["cc", "password", "pkce", "device", "refresh", "exchange", "jwt-bearer"],
    ),
    ("3", "Checking tokens", ["introspect"]),
    (
        "4",
        "Hardening — proof of possession and key-based client auth",
        ["dpop", "pkjwt", "pkjwt-dpop"],
    ),
    ("5", "Administration", ["dcr"]),
]


def tour() -> None:
    UI.tour = True
    try:
        _tour()
    finally:
        UI.tour = False


def _tour() -> None:
    S.results.clear()
    section(
        "Guided tour — verify-auth-python with IBM Verify",
        f"{TENANT_URL}   ·   Enter = run   s = skip   q = finish",
    )
    total = sum(len(names) for _, _, names in TOUR)
    i = 0
    for number, title, names in TOUR:
        print("\n\n" + bold(cyan(f"  ▌ Chapter {number} · {title}")))
        for name in names:
            i += 1
            label = FLOWS[name][0]
            if not ready(name):
                print(dim(f"    [{i}/{total}] {label} — not configured in .env, skipped"))
                S.results.append((label, "SKIP", "not configured"))
                continue
            interactive = name in ("pkce", "device", "dcr")
            prompt = f"[{i}/{total}] {label}{' (needs a person)' if interactive else ''} — Enter to run, s to skip, q to finish:"
            choice = ask(prompt, "").lower()
            if choice == "q":
                scoreboard("Tour summary")
                return
            if choice == "s":
                S.results.append((label, "SKIP", "skipped by presenter"))
                continue
            run_flow(name)
            pause("press Enter for the next flow")
    scoreboard("Tour summary")


def run_all(include_interactive: Optional[bool] = None, include_dcr: Optional[bool] = None) -> int:
    """Run every configured flow back to back (chapter order), then show the summary."""
    if include_interactive is None:
        include_interactive = (
            ask(
                "Include browser login (PKCE) and device flow? They need you to sign in. [Y/n]", "y"
            ).lower()
            != "n"
        )
    if include_dcr is None:
        include_dcr = (
            ask("Include DCR? It creates a temporary client and deletes it. [y/N]", "n").lower()
            == "y"
        )
    S.results.clear()
    S.include_dcr = include_dcr
    saved_pause = UI.pause_enabled
    UI.run_all = UI.tour = True
    UI.pause_enabled = False
    section("Running all flows", TENANT_URL)
    try:
        for number, title, names in TOUR:
            print("\n\n" + bold(cyan(f"  ▌ Chapter {number} · {title}")))
            for name in names:
                label = FLOWS[name][0]
                if not ready(name):
                    print(dim(f"    {label} — not configured in .env, skipped"))
                    S.results.append((label, "SKIP", "not configured"))
                elif name in ("pkce", "device") and not include_interactive:
                    S.results.append((label, "SKIP", "interactive — not selected"))
                elif name == "dcr" and not include_dcr:
                    S.results.append((label, "SKIP", "not selected"))
                else:
                    run_flow(name)
    finally:
        UI.run_all = UI.tour = False
        UI.pause_enabled = saved_pause
        S.include_dcr = False
    counts = scoreboard("All flows — summary")
    return 1 if counts["FAIL"] else 0


MENU_ROWS: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        "Getting tokens",
        [
            ("1", "cc", "Client credentials"),
            ("2", "password", "Password (ROPC)"),
            ("3", "pkce", "Authorization code + PKCE  🌐"),
            ("4", "device", "Device authorization  📱"),
            ("5", "refresh", "Refresh token"),
            ("6", "exchange", "Token exchange (on behalf of)"),
            ("7", "jwt-bearer", "JWT bearer grant"),
        ],
    ),
    (
        "Hardening",
        [
            ("8", "dpop", "DPoP — bound token, API, attacks"),
            ("9", "pkjwt", "private_key_jwt — no client secret, attacks"),
            ("10", "pkjwt-dpop", "private_key_jwt + DPoP together"),
        ],
    ),
    (
        "Tokens & tenant",
        [
            ("11", "introspect", "Introspect the last token"),
            ("12", "discovery", "OIDC discovery"),
            ("13", "jwks", "JWKS signing keys"),
            ("14", "dcr", "Dynamic client registration"),
        ],
    ),
]
MENU = {num: name for _, items in MENU_ROWS for num, name, _ in items}


def menu() -> None:
    while True:
        last = f"{S.last_source} · {S.last_token.get('token_type')}" if S.last_token else "—"
        print("\n" + cyan("╔" + "═" * 70 + "╗"))
        print(
            cyan("║") + bold("  IBM Verify  ·  verify-auth-python SDK demo".ljust(70)) + cyan("║")
        )
        print(cyan("║") + dim(f"  {TENANT_URL}".ljust(70)[:70]) + cyan("║"))
        print(cyan("╚" + "═" * 70 + "╝"))
        print(
            dim(
                f"  last token: {last}   ·   DPoP on every grant: "
                f"{'on' if S.dpop_everywhere else 'off'}   ·   tokens: "
                f"{'full' if S.show_tokens else 'masked'}"
            )
        )
        for group, items in MENU_ROWS:
            print("\n  " + bold(group))
            for num, name, label in items:
                dot = green("●") if ready(name) else dim("○")
                print(f"   {dot} {num:>2}  {label}")
        print(
            "\n  "
            + bold("r")
            + "  Run ALL flows   "
            + bold("t")
            + "  Guided tour   "
            + bold("a")
            + "  Smoke test   "
            + bold("s")
            + "  Settings   "
            + bold("0")
            + "  Exit"
        )
        print(dim("  ● ready   ○ needs settings in sample-scripts/.env"))
        choice = ask("\n  Choice:", "").lower()
        if not choice:
            continue
        if choice == "0":
            print(green("\n  👋 bye\n"))
            return
        if choice == "s":
            settings()
        elif choice == "r":
            run_all()
            S.results.clear()
            pause("press Enter for the menu")
        elif choice == "t":
            tour()
            S.results.clear()
            pause("press Enter for the menu")
        elif choice == "a":
            smoke(include_dcr=False)
            UI.smoke = False
            S.results.clear()
            pause("press Enter for the menu")
        elif choice in MENU:
            run_flow(MENU[choice])
            pause("press Enter for the menu")
        else:
            warn(f"unknown option '{choice}'")


def main() -> None:
    ap = argparse.ArgumentParser(description="IBM Verify SDK interactive demo")
    ap.add_argument("--flow", choices=sorted(FLOWS), help="run one flow and exit")
    ap.add_argument(
        "--smoke", action="store_true", help="run every non-interactive flow, then exit"
    )
    ap.add_argument(
        "--include-dcr", action="store_true", help="with --smoke: also create + delete a DCR client"
    )
    ap.add_argument("--tour", action="store_true", help="guided tour through every flow")
    ap.add_argument(
        "--all", action="store_true", help="run every flow back to back (incl. browser/device)"
    )
    ap.add_argument("--no-pause", action="store_true", help="do not stop between steps")
    ap.add_argument("--dpop", action="store_true", help="send a DPoP proof with every grant")
    ap.add_argument("--show-tokens", action="store_true", help="print tokens unmasked")
    args = ap.parse_args()

    if not TENANT_URL or S.client is None:
        fail("IBM_VERIFY_TENANT_URL is not set — add it to sample-scripts/.env")
        sys.exit(1)
    UI.pause_enabled = not args.no_pause
    S.dpop_everywhere = args.dpop
    S.show_tokens = args.show_tokens
    try:
        S.client.load_discovery(op_name=OP_NAME)
    except VerifyError as exc:
        warn(f"discovery failed ({exc}) — using default endpoint paths")

    try:
        if args.smoke:
            sys.exit(smoke(args.include_dcr))
        if args.flow:
            status = run_flow(args.flow)
            sys.exit(1 if status == "FAIL" else 0)
        if args.tour:
            tour()
            return
        if args.all:
            sys.exit(run_all(include_interactive=True, include_dcr=args.include_dcr))
        menu()
    except KeyboardInterrupt:
        print("\n")
    finally:
        if S.api:
            S.api.stop()


if __name__ == "__main__":
    main()
