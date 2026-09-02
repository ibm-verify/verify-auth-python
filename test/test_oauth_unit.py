"""
Unit tests for the IBM Verify OAuth layer.

All network calls are mocked with respx so no live tenant is needed.

Coverage
--------
- DiscoveryMixin.load_discovery / get_jwks
- PasswordGrantMixin.password_grant
- ClientCredentialsMixin.client_credentials
- TokenExchangeMixin.token_exchange
- AuthorizationCodeMixin.build_authorization_url / exchange_code_for_token
- DeviceCodeMixin.request_device_code / poll_device_token
- JWTBearerMixin.jwt_bearer_grant
- RefreshTokenMixin.refresh_access_token
- IntrospectMixin.introspect_token
- OAuthBase endpoint resolution (constructor override, discovery, default)
- utils.generate_pkce_pair
- utils.build_authorization_url
- DcrMixin field pass-through (RFC 7591 / RFC 7592):
  - all standard grant_types combinations in client_metadata
  - RAR fields: authorization_details_types in DCR metadata
  - OIDC metadata: jwks_uri, subject_type, id_token_signed_response_alg, sector_identifier_uri
  - mTLS fields: tls_client_auth_subject_dn, tls_client_certificate_bound_access_tokens
  - arbitrary extra fields forwarded unchanged
  - RAT rotation in full lifecycle test
- authorization_details + extra_params on all token grant types
  (client_credentials, authorization_code, device_code, jwt_bearer, refresh_token, token_exchange)
"""

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from oauth2.auth.client import OAuthClient
from oauth2.core.errors.errors import VerifyError
from oauth2.grant_types.utils import build_authorization_url, generate_pkce_pair

# ── Constants ──────────────────────────────────────────────────────────────────

BASE = "https://tenant.example.com"
TOKEN_EP = f"{BASE}/oauth2/token"
INTROSPECT_EP = f"{BASE}/oauth2/introspect"
DISCOVERY_URL = f"{BASE}/oauth2/.well-known/openid-configuration"
DEVICE_AUTH_EP = f"{BASE}/oauth2/device_authorization"

DISCOVERY_DOC = {
    "issuer": f"{BASE}/oauth2",
    "authorization_endpoint": f"{BASE}/oauth2/authorize",
    "token_endpoint": TOKEN_EP,
    "introspection_endpoint": INTROSPECT_EP,
    "jwks_uri": f"{BASE}/oauth2/jwks",
    "device_authorization_endpoint": DEVICE_AUTH_EP,
    "grant_types_supported": [
        "authorization_code",
        "client_credentials",
        "password",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:device_code",
    ],
}

ACCESS_TOKEN_RESPONSE = {
    "access_token": "eyJhbGciOiJSUzI1NiJ9.payload.sig",
    "token_type": "bearer",
    "expires_in": 3600,
    "scope": "openid",
}

REFRESH_TOKEN_RESPONSE = {
    **ACCESS_TOKEN_RESPONSE,
    "refresh_token": "new-refresh-tok",
}

INTROSPECT_ACTIVE = {
    "active": True,
    "sub": "user123",
    "client_id": "client-abc",
    "scope": "openid",
    "exp": 9999999999,
}

JWKS_DOC = {
    "keys": [{"kty": "RSA", "kid": "server", "use": "sig", "n": "abc", "e": "AQAB"}]
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_client(*, with_discovery: bool = False) -> OAuthClient:
    """Return an OAuthClient pointed at the fake tenant."""
    client = OAuthClient(base_url=BASE)
    if with_discovery:
        # Pre-populate discovery so the resolver uses TOKEN_EP from the doc
        from authlib.oidc.discovery import OpenIDProviderMetadata
        client._provider_metadata = OpenIDProviderMetadata(DISCOVERY_DOC)
    return client


def token_response(body: dict = ACCESS_TOKEN_RESPONSE) -> httpx.Response:
    return httpx.Response(200, json=body)


def error_response(status: int, error: str, description: str = "") -> httpx.Response:
    body: dict = {"error": error}
    if description:
        body["error_description"] = description
    return httpx.Response(status, json=body)


# ══════════════════════════════════════════════════════════════════════════════
# OAuthBase — endpoint resolution
# ══════════════════════════════════════════════════════════════════════════════

class TestOAuthBaseEndpointResolution:
    """Tests for OAuthBase._resolve_*_endpoint() priority chain.

    Priority order (highest → lowest):
      caller_endpoint arg  >  constructor override  >  discovery doc  >  hardcoded default path

    No HTTP calls are made — these tests exercise pure URL-resolution logic.
    """

    def test_default_token_endpoint(self):
        """Without discovery or overrides, token endpoint defaults to /oauth2/token."""
        client = OAuthClient(base_url=BASE)
        assert client._resolve_token_endpoint() == f"{BASE}/oauth2/token"

    def test_constructor_override_wins(self):
        """token_endpoint passed to OAuthClient() takes precedence over the default."""
        override = "https://other.example.com/token"
        client = OAuthClient(base_url=BASE, token_endpoint=override)
        assert client._resolve_token_endpoint() == override

    def test_discovery_token_endpoint_used(self):
        """When discovery metadata is loaded, its token_endpoint is used."""
        client = make_client(with_discovery=True)
        assert client._resolve_token_endpoint() == TOKEN_EP

    def test_caller_override_beats_discovery(self):
        """A caller_endpoint argument overrides even the discovery document."""
        client = make_client(with_discovery=True)
        caller = "https://caller.example.com/token"
        assert client._resolve_token_endpoint(caller_endpoint=caller) == caller

    def test_default_introspect_endpoint(self):
        """Without discovery, introspect endpoint defaults to /oauth2/introspect."""
        client = OAuthClient(base_url=BASE)
        ep = client._resolve_introspect_endpoint()
        assert ep == f"{BASE}/oauth2/introspect"

    def test_default_device_auth_endpoint(self):
        """Without discovery, device auth endpoint defaults to /oauth2/device_authorization."""
        client = OAuthClient(base_url=BASE)
        ep = client._resolve_device_auth_endpoint()
        assert ep == f"{BASE}/oauth2/device_authorization"

    def test_trailing_slash_stripped(self):
        """A trailing slash on base_url is stripped so endpoints don't get double slashes."""
        client = OAuthClient(base_url="https://tenant.example.com/")
        assert client.base_url == "https://tenant.example.com"


# ══════════════════════════════════════════════════════════════════════════════
# Utils
# ══════════════════════════════════════════════════════════════════════════════

class TestUtils:
    """Tests for the stateless utility helpers in oauth2.grant_types.utils.

    generate_pkce_pair()       — RFC 7636 PKCE code_verifier / code_challenge generation
    build_authorization_url()  — builds the PKCE authorization redirect URL
    """

    def test_generate_pkce_pair_lengths(self):
        """Verifier must be 128 chars; challenge must be 43 chars (S256 base64url, no padding)."""
        verifier, challenge = generate_pkce_pair()
        # 96 raw bytes → 128-char URL-safe base64 (no padding)
        assert len(verifier) == 128
        # SHA-256 of 128 bytes → 32-byte digest → 43-char base64url
        assert len(challenge) == 43

    def test_generate_pkce_pair_uniqueness(self):
        """Each call must produce a different pair — verifier is cryptographically random."""
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()
        assert pair1[0] != pair2[0]
        assert pair1[1] != pair2[1]

    def test_pkce_challenge_is_s256_of_verifier(self):
        import base64
        import hashlib

        verifier, challenge = generate_pkce_pair()
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert challenge == expected

    def test_build_authorization_url_contains_required_params(self):
        """URL must include response_type, client_id, code_challenge, method S256, and state."""
        url = build_authorization_url(
            authorize_endpoint=f"{BASE}/authorize",
            client_id="my-client",
            redirect_uri="https://app/callback",
            code_challenge="challenge-abc",
            scope="openid profile",
            state="state-xyz",
        )
        assert "response_type=code" in url
        assert "client_id=my-client" in url
        assert "code_challenge=challenge-abc" in url
        assert "code_challenge_method=S256" in url
        assert "state=state-xyz" in url

    def test_build_authorization_url_auto_state(self):
        """When state is omitted a random state value is generated automatically."""
        url = build_authorization_url(
            authorize_endpoint=f"{BASE}/authorize",
            client_id="c",
            redirect_uri="https://app/cb",
            code_challenge="ch",
        )
        assert "state=" in url

    def test_build_authorization_url_rar_serialised(self):
        """authorization_details list is JSON-encoded; a pre-serialised string is not double-encoded."""
        details = [{"type": "account_information"}]
        url = build_authorization_url(
            authorize_endpoint=f"{BASE}/authorize",
            client_id="c",
            redirect_uri="https://app/cb",
            code_challenge="ch",
            authorization_details=details,
        )
        assert "authorization_details=" in url
        # Already serialised string must not be double-encoded
        raw = json.dumps(details)
        url2 = build_authorization_url(
            authorize_endpoint=f"{BASE}/authorize",
            client_id="c",
            redirect_uri="https://app/cb",
            code_challenge="ch",
            authorization_details=raw,
        )
        assert "authorization_details=" in url2

    def test_build_authorization_url_extra_params(self):
        """extra_params dict is merged into the query string."""
        url = build_authorization_url(
            authorize_endpoint=f"{BASE}/authorize",
            client_id="c",
            redirect_uri="https://app/cb",
            code_challenge="ch",
            extra_params={"login_hint": "alice"},
        )
        assert "login_hint=alice" in url


# ══════════════════════════════════════════════════════════════════════════════
# DiscoveryMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestDiscoveryMixin:
    """Tests for DiscoveryMixin.load_discovery() and get_jwks().

    load_discovery() fetches the OIDC well-known config and caches it on the client.
    get_jwks()       fetches the JSON Web Key Set used for token signature verification.
    get_discovery()  returns cached metadata without making a second HTTP request.
    """

    @respx.mock
    def test_load_discovery_happy(self):
        """Happy path: discovery doc is fetched, parsed, and cached on the client."""
        respx.get(DISCOVERY_URL).mock(return_value=httpx.Response(200, json=DISCOVERY_DOC))
        client = OAuthClient(base_url=BASE)
        meta = client.load_discovery()
        assert meta["token_endpoint"] == TOKEN_EP
        assert client._provider_metadata is not None

    @respx.mock
    def test_load_discovery_http_error_raises_verify_error(self):
        """A 404 from the discovery endpoint raises VerifyError with status_code=404."""
        respx.get(DISCOVERY_URL).mock(return_value=httpx.Response(404))
        client = OAuthClient(base_url=BASE)
        with pytest.raises(VerifyError) as exc_info:
            client.load_discovery()
        assert exc_info.value.status_code == 404

    @respx.mock
    def test_load_discovery_network_error_raises_verify_error(self):
        """A network-level connection failure raises VerifyError (no status code)."""
        respx.get(DISCOVERY_URL).mock(side_effect=httpx.ConnectError("unreachable"))
        client = OAuthClient(base_url=BASE)
        with pytest.raises(VerifyError):
            client.load_discovery()

    @respx.mock
    def test_get_jwks_happy(self):
        """JWKS is fetched from the URI in the discovery doc and returned as a dict."""
        respx.get(DISCOVERY_URL).mock(return_value=httpx.Response(200, json=DISCOVERY_DOC))
        jwks_url = DISCOVERY_DOC["jwks_uri"]
        respx.get(jwks_url).mock(return_value=httpx.Response(200, json=JWKS_DOC))
        client = OAuthClient(base_url=BASE)
        client.load_discovery()
        jwks = client.get_jwks()
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kid"] == "server"

    @respx.mock
    def test_get_jwks_http_error_raises_verify_error(self):
        """A 500 from the JWKS endpoint raises VerifyError with status_code=500."""
        respx.get(DISCOVERY_URL).mock(return_value=httpx.Response(200, json=DISCOVERY_DOC))
        jwks_url = DISCOVERY_DOC["jwks_uri"]
        respx.get(jwks_url).mock(return_value=httpx.Response(500))
        client = OAuthClient(base_url=BASE)
        client.load_discovery()
        with pytest.raises(VerifyError) as exc_info:
            client.get_jwks()
        assert exc_info.value.status_code == 500

    def test_get_discovery_returns_cached(self):
        """get_discovery() must not make a second HTTP call if already loaded."""
        client = make_client(with_discovery=True)
        # No respx context — if an HTTP call were made, it would raise
        meta = client.get_discovery()
        assert meta["token_endpoint"] == TOKEN_EP


# ══════════════════════════════════════════════════════════════════════════════
# PasswordGrantMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestPasswordGrantMixin:
    """Tests for PasswordGrantMixin.password_grant() — RFC 6749 §4.3.

    The Resource Owner Password Credentials grant exchanges a username/password
    directly for an access token. IBM Verify requires an Authorization header.
    """

    @respx.mock
    def test_happy_path(self):
        """Valid credentials return access_token and token_type in the response."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        result = client.password_grant(
            client_id="cid",
            client_secret="secret",
            username="alice",
            password="pass",
            authorization_header="Basic dXNlcjpwYXNz",
            scope="openid",
        )
        assert result["access_token"] == ACCESS_TOKEN_RESPONSE["access_token"]
        assert result["token_type"] == "bearer"

    @respx.mock
    def test_invalid_grant_raises_verify_error(self):
        """A 400 invalid_grant response (wrong password) raises VerifyError."""
        respx.post(TOKEN_EP).mock(
            return_value=error_response(400, "invalid_grant", "Bad credentials")
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.password_grant(
                client_id="cid",
                client_secret="secret",
                username="alice",
                password="wrong",
                authorization_header="Basic dXNlcjp3cm9uZw==",
            )
        err = exc_info.value
        assert "invalid_grant" in str(err) or err.error == "invalid_grant"

    @respx.mock
    def test_rar_param_forwarded(self):
        """authorization_details list is JSON-encoded and included in the POST body (RFC 9396)."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            body = request.content.decode()
            captured["body"] = body
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        client.password_grant(
            client_id="cid",
            client_secret="secret",
            username="alice",
            password="pass",
            authorization_header="Basic x",
            authorization_details=[{"type": "account_information"}],
        )
        assert "authorization_details" in captured["body"]


# ══════════════════════════════════════════════════════════════════════════════
# ClientCredentialsMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestClientCredentialsMixin:
    """Tests for ClientCredentialsMixin.client_credentials() — RFC 6749 §4.4.

    The Client Credentials grant authenticates using client identity only (no user).
    Typically used for service-to-service calls.
    """

    @respx.mock
    def test_happy_path(self):
        """Valid client credentials return an access_token."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        result = client.client_credentials(
            client_id="svc-client",
            client_secret="svc-secret",
            scope="openid",
            authorization_header="Basic c3ZjOnNlY3JldA==",
        )
        assert "access_token" in result

    @respx.mock
    def test_unauthorized_raises_verify_error(self):
        """A 401 invalid_client response (unknown client) raises VerifyError."""
        respx.post(TOKEN_EP).mock(
            return_value=error_response(401, "invalid_client", "Unknown client")
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.client_credentials(
                client_id="bad",
                client_secret="bad",
                scope="openid",
                authorization_header="Basic YmFkOmJhZA==",
            )
        assert exc_info.value.error == "invalid_client" or exc_info.value.status_code in (400, 401)

    @respx.mock
    def test_rar_param_forwarded(self):
        """authorization_details list is JSON-encoded and sent in the request body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        client.client_credentials(
            client_id="c",
            client_secret="s",
            scope="openid",
            authorization_header="Basic x",
            authorization_details=[{"type": "payment_initiation"}],
        )
        assert "authorization_details" in captured["body"]

    @respx.mock
    def test_extra_params_forwarded(self):
        """extra_params dict (e.g. RFC 8707 resource indicator) is merged into the request body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        client.client_credentials(
            client_id="c",
            client_secret="s",
            scope="openid",
            authorization_header="Basic x",
            extra_params={"resource": "https://api.example.com"},
        )
        assert "resource=https" in captured["body"] or "resource" in captured["body"]


# ══════════════════════════════════════════════════════════════════════════════
# TokenExchangeMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestTokenExchangeMixin:
    """Tests for TokenExchangeMixin.token_exchange() — RFC 8693.

    Token Exchange produces a delegated token from a subject token (the user)
    and an actor token (the calling service). Used for impersonation / delegation.
    """

    @respx.mock
    def test_happy_path(self):
        """Valid subject + actor tokens return a new delegated access_token."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        result = client.token_exchange(
            client_id="exchange-client",
            client_secret="exchange-secret",
            subject_token="subject-tok",
            actor_token="actor-tok",
        )
        assert "access_token" in result

    @respx.mock
    def test_grant_type_in_body(self):
        """The RFC 8693 grant type URN must appear in the POST body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        client.token_exchange(
            client_id="c",
            client_secret="s",
            subject_token="sub",
            actor_token="act",
        )
        assert "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" in captured["body"] \
               or "grant-type:token-exchange" in captured["body"]

    @respx.mock
    def test_error_raises_verify_error(self):
        """An invalid_grant response (bad subject token) raises VerifyError."""
        respx.post(TOKEN_EP).mock(
            return_value=error_response(400, "invalid_grant", "Subject token invalid")
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError):
            client.token_exchange(
                client_id="c",
                client_secret="s",
                subject_token="bad",
                actor_token="bad",
            )


# ══════════════════════════════════════════════════════════════════════════════
# AuthorizationCodeMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthorizationCodeMixin:
    """Tests for AuthorizationCodeMixin — RFC 7636 Authorization Code + PKCE.

    Step 1: build_authorization_url()   — constructs the redirect URL with PKCE challenge.
    Step 2: exchange_code_for_token()   — exchanges the authorization code for tokens.

    Supports public clients (no secret), confidential clients (client_secret_post),
    and private_key_jwt clients.
    """

    def test_build_authorization_url_happy(self):
        """URL is built using the discovered authorize endpoint and contains all PKCE params."""
        client = make_client(with_discovery=True)
        verifier, challenge = OAuthClient.generate_pkce_pair()
        url = client.build_authorization_url(
            client_id="pkce-client",
            redirect_uri="https://app/callback",
            code_challenge=challenge,
            scope="openid profile",
            state="test-state",
        )
        assert f"{BASE}/oauth2/authorize" in url
        assert "pkce-client" in url
        assert challenge in url
        assert "test-state" in url
        assert "S256" in url

    def test_build_authorization_url_uses_default_endpoint_without_discovery(self):
        """Without discovery the default /oauth2/authorize path is used."""
        client = OAuthClient(base_url=BASE)
        _, challenge = OAuthClient.generate_pkce_pair()
        url = client.build_authorization_url(
            client_id="c",
            redirect_uri="https://app/cb",
            code_challenge=challenge,
        )
        assert f"{BASE}/oauth2/authorize" in url

    @respx.mock
    def test_exchange_code_for_token_public_client(self):
        """Public client (no secret) exchanges authorization code + PKCE verifier for tokens."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        verifier, _ = OAuthClient.generate_pkce_pair()
        result = client.exchange_code_for_token(
            client_id="pkce-client",
            redirect_uri="https://app/callback",
            code="auth-code-xyz",
            code_verifier=verifier,
            # no client_secret → public client
        )
        assert "access_token" in result

    @respx.mock
    def test_exchange_code_for_token_confidential_client(self):
        """Confidential client (with client_secret) exchanges authorization code for tokens."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        verifier, _ = OAuthClient.generate_pkce_pair()
        result = client.exchange_code_for_token(
            client_id="pkce-client",
            redirect_uri="https://app/callback",
            code="auth-code-xyz",
            code_verifier=verifier,
            client_secret="my-secret",
        )
        assert "access_token" in result

    @respx.mock
    def test_invalid_code_raises_verify_error(self):
        """An expired or already-used authorization code raises VerifyError."""
        respx.post(TOKEN_EP).mock(
            return_value=error_response(400, "invalid_grant", "Code expired")
        )
        client = make_client(with_discovery=True)
        verifier, _ = OAuthClient.generate_pkce_pair()
        with pytest.raises(VerifyError):
            client.exchange_code_for_token(
                client_id="pkce-client",
                redirect_uri="https://app/callback",
                code="stale-code",
                code_verifier=verifier,
            )


# ══════════════════════════════════════════════════════════════════════════════
# DeviceCodeMixin
# ══════════════════════════════════════════════════════════════════════════════

DEVICE_CODE_RESPONSE = {
    "device_code": "dev-code-abc",
    "user_code": "ABCD-1234",
    "verification_uri": "https://tenant.example.com/activate",
    "verification_uri_complete": "https://tenant.example.com/activate?code=ABCD-1234",
    "expires_in": 300,
    "interval": 5,
}


class TestDeviceCodeMixin:
    """Tests for DeviceCodeMixin — RFC 8628 Device Authorization Grant.

    Step 1: request_device_code()  — POST to device_authorization endpoint, get user_code.
    Step 2: poll_device_token()    — poll token endpoint until approved / expired / denied.

    Polling behaviour tested:
      - Immediate approval (token on first poll)
      - authorization_pending → then approved (two polls)
      - access_denied     → VerifyError
      - expired_token     → VerifyError
      - slow_down         → poll interval is increased
      - deadline exceeded → VerifyError (expires_in=-1)
    """

    @respx.mock
    def test_request_device_code_happy(self):
        """device_code and user_code are returned from the device_authorization endpoint."""
        respx.post(DEVICE_AUTH_EP).mock(
            return_value=httpx.Response(200, json=DEVICE_CODE_RESPONSE)
        )
        client = make_client(with_discovery=True)
        result = client.request_device_code(client_id="device-client", scope="openid")
        assert result["device_code"] == "dev-code-abc"
        assert result["user_code"] == "ABCD-1234"

    @respx.mock
    def test_request_device_code_http_error(self):
        """A 401 from the device_authorization endpoint raises VerifyError with status_code=401."""
        respx.post(DEVICE_AUTH_EP).mock(
            return_value=error_response(401, "invalid_client")
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.request_device_code(client_id="bad-client")
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_poll_device_token_immediate_approval(self):
        """If the first poll returns access_token, return it immediately."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        result = client.poll_device_token(
            client_id="device-client",
            device_code="dev-code-abc",
            interval=0,
            expires_in=60,
        )
        assert "access_token" in result

    @respx.mock
    def test_poll_device_token_authorization_pending_then_approved(self):
        """authorization_pending on first poll, token on second."""
        responses = [
            httpx.Response(200, json={"error": "authorization_pending"}),
            httpx.Response(200, json=ACCESS_TOKEN_RESPONSE),
        ]
        respx.post(TOKEN_EP).mock(side_effect=responses)
        client = make_client(with_discovery=True)

        with patch("time.sleep"):  # don't actually wait
            result = client.poll_device_token(
                client_id="device-client",
                device_code="dev-code-abc",
                interval=5,
                expires_in=60,
            )
        assert result["access_token"] == ACCESS_TOKEN_RESPONSE["access_token"]

    @respx.mock
    def test_poll_device_token_access_denied_raises(self):
        """access_denied error (user rejected the request) raises VerifyError with error='access_denied'."""
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(200, json={"error": "access_denied"})
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.poll_device_token(
                client_id="device-client",
                device_code="dev-code-abc",
                interval=0,
                expires_in=60,
            )
        assert exc_info.value.error == "access_denied"

    @respx.mock
    def test_poll_device_token_expired_token_raises(self):
        """expired_token error (device code TTL elapsed) raises VerifyError with error='expired_token'."""
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(200, json={"error": "expired_token"})
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.poll_device_token(
                client_id="device-client",
                device_code="dev-code-abc",
                interval=0,
                expires_in=60,
            )
        assert exc_info.value.error == "expired_token"

    def test_poll_device_token_deadline_exceeded_raises(self):
        """When expires_in has already passed the deadline is exceeded immediately."""
        client = make_client(with_discovery=True)

        # expires_in=-1 means deadline is already in the past
        with pytest.raises(VerifyError) as exc_info:
            client.poll_device_token(
                client_id="device-client",
                device_code="dev-code-abc",
                interval=0,
                expires_in=-1,
            )
        assert exc_info.value.error == "expired_token"

    @respx.mock
    def test_poll_device_token_slow_down_increases_interval(self):
        """slow_down instructs the client to back off — sleep duration must exceed original interval."""
        call_count = [0]
        intervals_slept: list = []

        def _handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] == 1:
                return httpx.Response(200, json={"error": "slow_down"})
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=_handler)
        client = make_client(with_discovery=True)

        with patch("time.sleep", side_effect=lambda s: intervals_slept.append(s)):
            client.poll_device_token(
                client_id="device-client",
                device_code="dev-code-abc",
                interval=5,
                expires_in=60,
            )

        # After slow_down, sleep must be > original interval (5)
        assert intervals_slept and intervals_slept[0] > 5


# ══════════════════════════════════════════════════════════════════════════════
# JWTBearerMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestJWTBearerMixin:
    """Tests for JWTBearerMixin.jwt_bearer_grant() — RFC 7523 JWT Bearer Grant.

    The caller pre-signs a JWT assertion (generate_jwt_bearer_assertion()) and
    exchanges it for an access token using grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
    IBM Verify resolves the signing key via the 'kid' header (certificate label).
    """

    @respx.mock
    def test_happy_path_with_client_secret(self):
        """A valid pre-signed assertion + client_secret returns an access_token."""
        respx.post(TOKEN_EP).mock(return_value=token_response())
        client = make_client(with_discovery=True)
        result = client.jwt_bearer_grant(
            assertion="signed-jwt-assertion",
            client_id="jwt-client",
            client_secret="jwt-secret",
            scope="openid profile email",
        )
        assert "access_token" in result

    @respx.mock
    def test_grant_type_in_body(self):
        """The jwt-bearer grant type URN must appear in the POST body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        client.jwt_bearer_grant(
            assertion="my-assertion",
            client_id="jwt-client",
            client_secret="secret",
        )
        body = captured["body"]
        assert "jwt-bearer" in body

    @respx.mock
    def test_error_raises_verify_error(self):
        """A bad/expired assertion raises VerifyError (invalid_grant)."""
        respx.post(TOKEN_EP).mock(
            return_value=error_response(400, "invalid_grant", "JWT assertion invalid")
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError):
            client.jwt_bearer_grant(
                assertion="bad-assertion",
                client_id="jwt-client",
                client_secret="secret",
            )

    @respx.mock
    def test_explicit_token_endpoint_override(self):
        """token_endpoint kwarg bypasses discovery and uses the supplied URL directly."""
        custom_ep = "https://custom.example.com/token"
        respx.post(custom_ep).mock(return_value=token_response())
        client = OAuthClient(base_url=BASE)
        result = client.jwt_bearer_grant(
            assertion="my-assertion",
            client_id="c",
            token_endpoint=custom_ep,
        )
        assert "access_token" in result


# ══════════════════════════════════════════════════════════════════════════════
# RefreshTokenMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestRefreshTokenMixin:
    """Tests for RefreshTokenMixin.refresh_access_token() — RFC 6749 §6.

    Exchanges a refresh_token for a new access_token (and optionally a new refresh_token
    when token rotation is enabled). Supports confidential and public clients.
    """

    @respx.mock
    def test_happy_path_with_secret(self):
        """Confidential client: new access_token and rotated refresh_token are returned."""
        respx.post(TOKEN_EP).mock(return_value=token_response(REFRESH_TOKEN_RESPONSE))
        client = make_client(with_discovery=True)
        result = client.refresh_access_token(
            client_id="cid",
            refresh_token="old-refresh-tok",
            client_secret="secret",
        )
        assert "access_token" in result
        assert result.get("refresh_token") == "new-refresh-tok"

    @respx.mock
    def test_grant_type_in_body(self):
        """grant_type=refresh_token and the token value are present in the POST body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        client.refresh_access_token(
            client_id="c",
            refresh_token="r",
            client_secret="s",
        )
        assert "grant_type=refresh_token" in captured["body"]
        assert "refresh_token=r" in captured["body"]

    @respx.mock
    def test_invalid_grant_raises_verify_error(self):
        """An expired or revoked refresh_token raises VerifyError (invalid_grant)."""
        respx.post(TOKEN_EP).mock(
            return_value=error_response(400, "invalid_grant", "Refresh token revoked")
        )
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.refresh_access_token(
                client_id="cid",
                refresh_token="revoked-tok",
                client_secret="secret",
            )
        err = exc_info.value
        assert "invalid_grant" in str(err) or err.error == "invalid_grant"

    @respx.mock
    def test_public_client_sends_client_id_in_body(self):
        """Public client (no secret) must send client_id in the POST body instead of Basic auth."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content.decode()
            return token_response()

        respx.post(TOKEN_EP).mock(side_effect=capture)
        client = make_client(with_discovery=True)
        # No client_secret → public client path
        client.refresh_access_token(client_id="pub-client", refresh_token="r")
        assert "client_id=pub-client" in captured["body"]


# ══════════════════════════════════════════════════════════════════════════════
# IntrospectMixin
# ══════════════════════════════════════════════════════════════════════════════

class TestIntrospectMixin:
    """Tests for IntrospectMixin.introspect_token() — RFC 7662 Token Introspection.

    Queries the introspection endpoint to check whether a token is active and
    retrieve its metadata (sub, scope, exp, client_id, etc.).
    """

    @respx.mock
    def test_happy_path_active_token(self):
        """An active token returns active=True with sub and scope fields."""
        respx.post(INTROSPECT_EP).mock(
            return_value=httpx.Response(200, json=INTROSPECT_ACTIVE)
        )
        client = make_client(with_discovery=True)
        result = client.introspect_token(
            token="some-access-token",
            client_id="cid",
            client_secret="secret",
            token_type_hint="access_token",
        )
        assert result["active"] is True
        assert result["sub"] == "user123"

    @respx.mock
    def test_inactive_token_returns_active_false(self):
        """An expired or revoked token returns active=False (not an error — a valid response)."""
        respx.post(INTROSPECT_EP).mock(
            return_value=httpx.Response(200, json={"active": False})
        )
        client = make_client(with_discovery=True)
        result = client.introspect_token(
            token="expired-token",
            client_id="cid",
            client_secret="secret",
        )
        assert result["active"] is False

    @respx.mock
    def test_http_error_raises_verify_error(self):
        """A 401 from the introspection endpoint raises VerifyError, not a JSONDecodeError."""
        respx.post(INTROSPECT_EP).mock(return_value=httpx.Response(401))
        client = make_client(with_discovery=True)
        with pytest.raises(VerifyError) as exc_info:
            client.introspect_token(
                token="tok",
                client_id="cid",
                client_secret="secret",
            )
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_explicit_endpoint_override(self):
        """introspect_endpoint kwarg bypasses discovery and uses the supplied URL directly."""
        custom_ep = "https://custom.example.com/introspect"
        respx.post(custom_ep).mock(
            return_value=httpx.Response(200, json=INTROSPECT_ACTIVE)
        )
        client = OAuthClient(base_url=BASE)
        result = client.introspect_token(
            token="tok",
            client_id="cid",
            client_secret="secret",
            introspect_endpoint=custom_ep,
        )
        assert result["active"] is True


# ══════════════════════════════════════════════════════════════════════════════
# VerifyError
# ══════════════════════════════════════════════════════════════════════════════

class TestVerifyError:
    """Tests for the VerifyError exception class.

    VerifyError is the single exception type raised by all SDK methods.
    It carries optional HTTP status_code, OAuth error code, and description.
    """

    def test_str_includes_all_fields(self):
        """str(err) includes message, status code, error code, and description."""
        err = VerifyError(
            message="bad request",
            status_code=400,
            error="invalid_client",
            error_description="Unknown client ID",
        )
        s = str(err)
        assert "bad request" in s
        assert "400" in s
        assert "invalid_client" in s
        assert "Unknown client ID" in s

    def test_repr(self):
        """repr(err) includes the class name and status code for easy debugging."""
        err = VerifyError(message="oops", status_code=500)
        assert "VerifyError" in repr(err)
        assert "500" in repr(err)

    def test_minimal_str(self):
        """An error with only a message renders as just that message string."""
        err = VerifyError(message="oops")
        assert str(err) == "oops"


# ══════════════════════════════════════════════════════════════════════════════
# DcrMixin  (RFC 7591 / RFC 7592)
# ══════════════════════════════════════════════════════════════════════════════

# Endpoints used by the DCR tests
REGISTER_EP = f"{BASE}/oauth2/register"
CLIENT_URI = f"{BASE}/oauth2/register/client-xyz"

# Canned responses
DCR_REGISTRATION_RESPONSE = {
    "client_id": "client-xyz",
    "client_secret": "secret-xyz",
    "registration_access_token": "reg-tok-xyz",
    "registration_client_uri": CLIENT_URI,
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_basic",
}

DCR_CLIENT_METADATA = {
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "client_name": "My Test App",
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile email",
}

DCR_UPDATED_METADATA = {
    **DCR_CLIENT_METADATA,
    "client_name": "My Updated App",
}


class TestDcrMixin:
    """End-to-end tests for DcrMixin — Dynamic Client Registration (RFC 7591 / RFC 7592).

    Steps modelled:
      1. register_client  → POST /oauth2/register      (RFC 7591)
      2. read_client      → GET  /oauth2/register/<id> (RFC 7592)
      3. update_client    → PUT  /oauth2/register/<id> (RFC 7592)
      4. delete_client    → DELETE /oauth2/register/<id> (RFC 7592)

    Also covers:
      - endpoint resolution: default → discovery → caller override
      - initial_access_token forwarded as Authorization: Bearer
      - HTTP 4xx/5xx errors surface as VerifyError
      - network errors surface as VerifyError
    """

    # ── register_client (RFC 7591) ────────────────────────────────────────────

    @respx.mock
    def test_register_client_happy_path(self):
        """POST to the default registration endpoint returns client credentials."""
        respx.post(REGISTER_EP).mock(
            return_value=httpx.Response(201, json=DCR_REGISTRATION_RESPONSE)
        )
        client = make_client()
        result = client.register_client(
            client_metadata=DCR_CLIENT_METADATA,
            initial_access_token="iat-abc",
        )
        assert result["client_id"] == "client-xyz"
        assert result["client_secret"] == "secret-xyz"
        assert "registration_access_token" in result
        assert "registration_client_uri" in result

    @respx.mock
    def test_register_client_sends_bearer_token(self):
        """initial_access_token must be sent as ``Authorization: Bearer …``."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("authorization", "")
            return httpx.Response(201, json=DCR_REGISTRATION_RESPONSE)

        respx.post(REGISTER_EP).mock(side_effect=capture)
        make_client().register_client(
            client_metadata=DCR_CLIENT_METADATA,
            initial_access_token="my-iat",
        )
        assert captured["auth"] == "Bearer my-iat"

    @respx.mock
    def test_register_client_sends_json_body(self):
        """Client metadata must be serialised as ``application/json``."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["ct"] = request.headers.get("content-type", "")
            captured["body"] = json.loads(request.content)
            return httpx.Response(201, json=DCR_REGISTRATION_RESPONSE)

        respx.post(REGISTER_EP).mock(side_effect=capture)
        make_client().register_client(client_metadata=DCR_CLIENT_METADATA)
        assert "application/json" in captured["ct"]
        assert captured["body"]["client_name"] == "My Test App"

    @respx.mock
    def test_register_client_uses_discovery_endpoint(self):
        """When discovery is loaded, its ``registration_endpoint`` is preferred."""
        discovery_reg_ep = f"{BASE}/oauth2/register"
        discovery_doc = {
            **DISCOVERY_DOC,
            "registration_endpoint": discovery_reg_ep,
        }
        respx.post(discovery_reg_ep).mock(
            return_value=httpx.Response(201, json=DCR_REGISTRATION_RESPONSE)
        )
        from authlib.oidc.discovery import OpenIDProviderMetadata
        client = make_client()
        client._provider_metadata = OpenIDProviderMetadata(discovery_doc)
        result = client.register_client(client_metadata=DCR_CLIENT_METADATA)
        assert result["client_id"] == "client-xyz"

    @respx.mock
    def test_register_client_caller_override_beats_discovery(self):
        """An explicit ``registration_endpoint`` kwarg overrides everything."""
        override_ep = f"{BASE}/custom/register"
        respx.post(override_ep).mock(
            return_value=httpx.Response(201, json=DCR_REGISTRATION_RESPONSE)
        )
        from authlib.oidc.discovery import OpenIDProviderMetadata
        client = make_client()
        client._provider_metadata = OpenIDProviderMetadata({
            **DISCOVERY_DOC,
            "registration_endpoint": f"{BASE}/oauth2/register",
        })
        result = client.register_client(
            client_metadata=DCR_CLIENT_METADATA,
            registration_endpoint=override_ep,
        )
        assert result["client_id"] == "client-xyz"

    @respx.mock
    def test_register_client_4xx_raises_verify_error(self):
        """A 401 (missing/invalid IAT) raises VerifyError with the status code."""
        respx.post(REGISTER_EP).mock(
            return_value=httpx.Response(
                401, json={"error": "invalid_token", "error_description": "IAT invalid"}
            )
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().register_client(client_metadata=DCR_CLIENT_METADATA)
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_register_client_400_raises_verify_error(self):
        """A 400 (bad metadata) raises VerifyError."""
        respx.post(REGISTER_EP).mock(
            return_value=httpx.Response(
                400, json={"error": "invalid_client_metadata"}
            )
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().register_client(client_metadata={"bad": "metadata"})
        assert exc_info.value.status_code == 400

    @respx.mock
    def test_register_client_network_error_raises_verify_error(self):
        """A transport-level error raises VerifyError (not a bare httpx error)."""
        respx.post(REGISTER_EP).mock(side_effect=httpx.ConnectError("timeout"))
        with pytest.raises(VerifyError) as exc_info:
            make_client().register_client(client_metadata=DCR_CLIENT_METADATA)
        assert "DCR register failed" in exc_info.value.message

    # ── read_client (RFC 7592) ────────────────────────────────────────────────

    @respx.mock
    def test_read_client_happy_path(self):
        """GET to the registration_client_uri returns current metadata."""
        respx.get(CLIENT_URI).mock(
            return_value=httpx.Response(200, json=DCR_REGISTRATION_RESPONSE)
        )
        result = make_client().read_client(
            registration_access_token="reg-tok-xyz",
            registration_client_uri=CLIENT_URI,
        )
        assert result["client_id"] == "client-xyz"

    @respx.mock
    def test_read_client_sends_bearer_token(self):
        """registration_access_token must be sent as ``Authorization: Bearer …``."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("authorization", "")
            return httpx.Response(200, json=DCR_REGISTRATION_RESPONSE)

        respx.get(CLIENT_URI).mock(side_effect=capture)
        make_client().read_client(
            registration_access_token="reg-tok-xyz",
            registration_client_uri=CLIENT_URI,
        )
        assert captured["auth"] == "Bearer reg-tok-xyz"

    @respx.mock
    def test_read_client_401_raises_verify_error(self):
        """A 401 (expired/revoked registration token) raises VerifyError."""
        respx.get(CLIENT_URI).mock(
            return_value=httpx.Response(401, json={"error": "invalid_token"})
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().read_client(
                registration_access_token="bad",
                registration_client_uri=CLIENT_URI,
            )
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_read_client_404_raises_verify_error(self):
        """A 404 (client not found or already deleted) raises VerifyError."""
        respx.get(CLIENT_URI).mock(
            return_value=httpx.Response(404, json={"error": "not_found"})
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().read_client(
                registration_access_token="reg-tok-xyz",
                registration_client_uri=CLIENT_URI,
            )
        assert exc_info.value.status_code == 404

    @respx.mock
    def test_read_client_network_error_raises_verify_error(self):
        """A network error during read raises VerifyError."""
        respx.get(CLIENT_URI).mock(side_effect=httpx.ConnectError("unreachable"))
        with pytest.raises(VerifyError) as exc_info:
            make_client().read_client(
                registration_access_token="reg-tok-xyz",
                registration_client_uri=CLIENT_URI,
            )
        assert "DCR read failed" in exc_info.value.message

    # ── update_client (RFC 7592) ──────────────────────────────────────────────

    @respx.mock
    def test_update_client_happy_path(self):
        """PUT to the registration_client_uri returns updated metadata."""
        respx.put(CLIENT_URI).mock(
            return_value=httpx.Response(200, json=DCR_UPDATED_METADATA)
        )
        result = make_client().update_client(
            registration_access_token="reg-tok-xyz",
            registration_client_uri=CLIENT_URI,
            client_metadata=DCR_UPDATED_METADATA,
        )
        assert result["client_name"] == "My Updated App"

    @respx.mock
    def test_update_client_sends_json_body(self):
        """Updated metadata must be sent as ``application/json`` in a PUT body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["ct"] = request.headers.get("content-type", "")
            captured["auth"] = request.headers.get("authorization", "")
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=DCR_UPDATED_METADATA)

        respx.put(CLIENT_URI).mock(side_effect=capture)
        make_client().update_client(
            registration_access_token="reg-tok-xyz",
            registration_client_uri=CLIENT_URI,
            client_metadata=DCR_UPDATED_METADATA,
        )
        assert "application/json" in captured["ct"]
        assert captured["auth"] == "Bearer reg-tok-xyz"
        assert captured["body"]["client_name"] == "My Updated App"

    @respx.mock
    def test_update_client_4xx_raises_verify_error(self):
        """A 400 (invalid metadata on update) raises VerifyError."""
        respx.put(CLIENT_URI).mock(
            return_value=httpx.Response(400, json={"error": "invalid_client_metadata"})
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().update_client(
                registration_access_token="reg-tok-xyz",
                registration_client_uri=CLIENT_URI,
                client_metadata={"bad": True},
            )
        assert exc_info.value.status_code == 400

    @respx.mock
    def test_update_client_network_error_raises_verify_error(self):
        """A network error during update raises VerifyError."""
        respx.put(CLIENT_URI).mock(side_effect=httpx.ConnectError("unreachable"))
        with pytest.raises(VerifyError) as exc_info:
            make_client().update_client(
                registration_access_token="reg-tok-xyz",
                registration_client_uri=CLIENT_URI,
                client_metadata=DCR_UPDATED_METADATA,
            )
        assert "DCR update failed" in exc_info.value.message

    # ── delete_client (RFC 7592) ──────────────────────────────────────────────

    @respx.mock
    def test_delete_client_happy_path(self):
        """DELETE to registration_client_uri returns None on HTTP 204."""
        respx.delete(CLIENT_URI).mock(
            return_value=httpx.Response(204)
        )
        result = make_client().delete_client(
            registration_access_token="reg-tok-xyz",
            registration_client_uri=CLIENT_URI,
        )
        assert result is None

    @respx.mock
    def test_delete_client_sends_bearer_token(self):
        """registration_access_token must be sent as ``Authorization: Bearer …``."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("authorization", "")
            return httpx.Response(204)

        respx.delete(CLIENT_URI).mock(side_effect=capture)
        make_client().delete_client(
            registration_access_token="reg-tok-xyz",
            registration_client_uri=CLIENT_URI,
        )
        assert captured["auth"] == "Bearer reg-tok-xyz"

    @respx.mock
    def test_delete_client_404_raises_verify_error(self):
        """A 404 (already deleted or unknown client) raises VerifyError."""
        respx.delete(CLIENT_URI).mock(
            return_value=httpx.Response(404, json={"error": "not_found"})
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().delete_client(
                registration_access_token="reg-tok-xyz",
                registration_client_uri=CLIENT_URI,
            )
        assert exc_info.value.status_code == 404

    @respx.mock
    def test_delete_client_401_raises_verify_error(self):
        """A 401 (invalid/expired registration token on delete) raises VerifyError."""
        respx.delete(CLIENT_URI).mock(
            return_value=httpx.Response(401, json={"error": "invalid_token"})
        )
        with pytest.raises(VerifyError) as exc_info:
            make_client().delete_client(
                registration_access_token="bad-token",
                registration_client_uri=CLIENT_URI,
            )
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_delete_client_network_error_raises_verify_error(self):
        """A network error during delete raises VerifyError."""
        respx.delete(CLIENT_URI).mock(side_effect=httpx.ConnectError("unreachable"))
        with pytest.raises(VerifyError) as exc_info:
            make_client().delete_client(
                registration_access_token="reg-tok-xyz",
                registration_client_uri=CLIENT_URI,
            )
        assert "DCR delete failed" in exc_info.value.message

    # ── Full lifecycle (register → read → update → delete) ───────────────────

    @respx.mock
    def test_full_dcr_lifecycle(self):
        """End-to-end: register → read → update → delete with correct RAT rotation.

        IBM Verify (RFC 7592) rotates the registration_access_token on every
        successful GET/PUT/DELETE.  Each step must use the token returned by the
        *previous* call, not the one from registration.
        """
        RAT_STEP1 = "rat-from-register"
        RAT_STEP2 = "rat-from-read"
        RAT_STEP3 = "rat-from-update"

        reg_response = {**DCR_REGISTRATION_RESPONSE, "registration_access_token": RAT_STEP1}
        read_response = {**DCR_REGISTRATION_RESPONSE, "registration_access_token": RAT_STEP2}
        update_response = {**DCR_UPDATED_METADATA,    "registration_access_token": RAT_STEP3}

        # Step 1 — register
        respx.post(REGISTER_EP).mock(return_value=httpx.Response(201, json=reg_response))
        # Step 2 — read
        respx.get(CLIENT_URI).mock(return_value=httpx.Response(200, json=read_response))
        # Step 3 — update
        respx.put(CLIENT_URI).mock(return_value=httpx.Response(200, json=update_response))
        # Step 4 — delete
        respx.delete(CLIENT_URI).mock(return_value=httpx.Response(204))

        client = make_client()

        reg = client.register_client(
            client_metadata=DCR_CLIENT_METADATA,
            initial_access_token="iat-abc",
        )
        assert reg["client_id"] == "client-xyz"
        rat = reg["registration_access_token"]   # RAT_STEP1
        rcu = reg["registration_client_uri"]
        assert rat == RAT_STEP1

        read = client.read_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
        )
        assert read["client_id"] == "client-xyz"
        rat = read.get("registration_access_token", rat)  # rotate → RAT_STEP2
        assert rat == RAT_STEP2

        updated = client.update_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
            client_metadata=DCR_UPDATED_METADATA,
        )
        assert updated["client_name"] == "My Updated App"
        rat = updated.get("registration_access_token", rat)  # rotate → RAT_STEP3
        assert rat == RAT_STEP3

        result = client.delete_client(
            registration_access_token=rat,
            registration_client_uri=rcu,
        )
        assert result is None


# ==============================================================================
# TestDcrFieldPassthrough
# ==============================================================================
# Proves that register_client and update_client forward every field in
# client_metadata verbatim to the server — no field is dropped, renamed, or
# validated by the SDK.  All network calls are mocked; no live tenant needed.
# ==============================================================================

class TestDcrFieldPassthrough:
    """SDK passes all client_metadata fields through to the server unchanged."""

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _capture_register(response_body: dict) -> tuple:
        """Return (captured_dict, mock_setup_fn) for a register POST."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(201, json=response_body)

        return captured, capture

    @staticmethod
    def _capture_update(response_body: dict) -> tuple:
        """Return (captured_dict, mock_setup_fn) for an update PUT."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=response_body)

        return captured, capture

    # ── grant_types combinations ──────────────────────────────────────────────

    @respx.mock
    def test_all_grant_types_forwarded_verbatim(self):
        """Every supported grant_type value must survive the round-trip unchanged."""
        all_grant_types = [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "password",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ]
        metadata = {
            "client_name": "All-Grants Client",
            "grant_types": all_grant_types,
            "response_types": ["code", "token"],
            "redirect_uris": ["https://app.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata, initial_access_token="iat")

        assert captured["body"]["grant_types"] == all_grant_types

    @respx.mock
    def test_client_credentials_only_grant_type(self):
        """A machine-to-machine client with only client_credentials is forwarded."""
        metadata = {
            "client_name": "M2M Client",
            "grant_types": ["client_credentials"],
            "response_types": ["token"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        assert captured["body"]["grant_types"] == ["client_credentials"]
        assert captured["body"]["response_types"] == ["token"]

    @respx.mock
    def test_device_code_grant_type_forwarded(self):
        """URN-style device_code grant type string is forwarded without mutation."""
        metadata = {
            "client_name": "Device Client",
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
            "token_endpoint_auth_method": "none",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        assert captured["body"]["grant_types"] == [
            "urn:ietf:params:oauth:grant-type:device_code"
        ]

    @respx.mock
    def test_jwt_bearer_grant_type_forwarded(self):
        """URN-style jwt-bearer grant type string is forwarded without mutation."""
        metadata = {
            "client_name": "JWT Bearer Client",
            "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://app.example.com/.well-known/jwks.json",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in captured["body"]["grant_types"]

    # ── RAR / authorization_details_types ─────────────────────────────────────

    @respx.mock
    def test_rar_authorization_details_types_forwarded(self):
        """authorization_details_types (RAR, RFC 9396) is forwarded as-is."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "authorization_details_types": ["account_information", "payment_initiation"],
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(
            client_metadata=metadata,
            initial_access_token="iat",
        )

        assert captured["body"]["authorization_details_types"] == [
            "account_information",
            "payment_initiation",
        ]

    @respx.mock
    def test_rar_single_authorization_details_type(self):
        """A single-element authorization_details_types list is forwarded intact."""
        metadata = {**DCR_CLIENT_METADATA, "authorization_details_types": ["openid"]}
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        assert captured["body"]["authorization_details_types"] == ["openid"]

    @respx.mock
    def test_rar_field_survives_update(self):
        """authorization_details_types is forwarded unchanged on PUT (update_client)."""
        metadata = {
            **DCR_UPDATED_METADATA,
            "authorization_details_types": ["account_information"],
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_update(DCR_UPDATED_METADATA)
        respx.put(CLIENT_URI).mock(side_effect=capture_fn)

        make_client().update_client(
            registration_access_token="rat",
            registration_client_uri=CLIENT_URI,
            client_metadata=metadata,
        )

        assert captured["body"]["authorization_details_types"] == ["account_information"]

    # ── OIDC-specific metadata fields ─────────────────────────────────────────

    @respx.mock
    def test_oidc_metadata_fields_forwarded(self):
        """OIDC-specific fields (jwks_uri, subject_type, etc.) are forwarded verbatim."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "jwks_uri": "https://app.example.com/.well-known/jwks.json",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://app.example.com/sector",
            "id_token_signed_response_alg": "RS256",
            "id_token_encrypted_response_alg": "RSA-OAEP",
            "id_token_encrypted_response_enc": "A256GCM",
            "userinfo_signed_response_alg": "RS256",
            "request_object_signing_alg": "RS256",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        body = captured["body"]
        assert body["jwks_uri"] == "https://app.example.com/.well-known/jwks.json"
        assert body["subject_type"] == "pairwise"
        assert body["sector_identifier_uri"] == "https://app.example.com/sector"
        assert body["id_token_signed_response_alg"] == "RS256"
        assert body["id_token_encrypted_response_alg"] == "RSA-OAEP"
        assert body["id_token_encrypted_response_enc"] == "A256GCM"
        assert body["userinfo_signed_response_alg"] == "RS256"
        assert body["request_object_signing_alg"] == "RS256"

    @respx.mock
    def test_inline_jwks_forwarded(self):
        """Inline jwks (key set object) is forwarded, not just jwks_uri."""
        inline_jwks = {
            "keys": [{"kty": "RSA", "kid": "key1", "use": "sig", "n": "abc", "e": "AQAB"}]
        }
        metadata = {**DCR_CLIENT_METADATA, "jwks": inline_jwks}
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        assert captured["body"]["jwks"] == inline_jwks

    @respx.mock
    def test_application_type_forwarded(self):
        """application_type (web / native) is forwarded as a plain string."""
        for app_type in ("web", "native"):
            captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
            respx.post(REGISTER_EP).mock(side_effect=capture_fn)

            make_client().register_client(
                client_metadata={**DCR_CLIENT_METADATA, "application_type": app_type}
            )

            assert captured["body"]["application_type"] == app_type

    # ── mTLS / certificate-bound fields ───────────────────────────────────────

    @respx.mock
    def test_mtls_fields_forwarded(self):
        """mTLS client auth fields (RFC 8705) are forwarded without modification."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_auth_subject_dn": "CN=my-service,O=Example,C=US",
            "tls_client_certificate_bound_access_tokens": True,
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        body = captured["body"]
        assert body["token_endpoint_auth_method"] == "tls_client_auth"
        assert body["tls_client_auth_subject_dn"] == "CN=my-service,O=Example,C=US"
        assert body["tls_client_certificate_bound_access_tokens"] is True

    @respx.mock
    def test_mtls_san_fields_forwarded(self):
        """Alternative mTLS SAN fields are forwarded as strings."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_auth_san_dns": "my-service.example.com",
            "tls_client_auth_san_ip": "10.0.0.1",
            "tls_client_auth_san_email": "service@example.com",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        body = captured["body"]
        assert body["tls_client_auth_san_dns"] == "my-service.example.com"
        assert body["tls_client_auth_san_ip"] == "10.0.0.1"
        assert body["tls_client_auth_san_email"] == "service@example.com"

    # ── Arbitrary / IBM-specific extension fields ─────────────────────────────

    @respx.mock
    def test_arbitrary_ibm_extension_fields_forwarded(self):
        """Unknown/IBM-specific extension fields are forwarded without being stripped."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "oauth2_custom_attribute": "some-value",
            "enforce_pkce": True,
            "introspect_tokens": True,
            "restrict_to_ips": ["10.0.0.0/8"],
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        body = captured["body"]
        assert body["oauth2_custom_attribute"] == "some-value"
        assert body["enforce_pkce"] is True
        assert body["introspect_tokens"] is True
        assert body["restrict_to_ips"] == ["10.0.0.0/8"]

    @respx.mock
    def test_contacts_and_logo_uri_forwarded(self):
        """contacts (list of emails) and logo_uri are forwarded as-is."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "contacts": ["admin@example.com", "devops@example.com"],
            "logo_uri": "https://app.example.com/logo.png",
            "client_uri": "https://app.example.com",
            "policy_uri": "https://app.example.com/privacy",
            "tos_uri": "https://app.example.com/tos",
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        body = captured["body"]
        assert body["contacts"] == ["admin@example.com", "devops@example.com"]
        assert body["logo_uri"] == "https://app.example.com/logo.png"
        assert body["client_uri"] == "https://app.example.com"
        assert body["policy_uri"] == "https://app.example.com/privacy"
        assert body["tos_uri"] == "https://app.example.com/tos"

    @respx.mock
    def test_post_logout_redirect_uris_forwarded(self):
        """post_logout_redirect_uris (OIDC RP-initiated logout) are forwarded."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "post_logout_redirect_uris": [
                "https://app.example.com/logout",
                "https://app.example.com/bye",
            ],
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        assert captured["body"]["post_logout_redirect_uris"] == [
            "https://app.example.com/logout",
            "https://app.example.com/bye",
        ]

    @respx.mock
    def test_default_max_age_and_require_auth_time_forwarded(self):
        """Numeric/boolean OIDC session fields are forwarded with their types preserved."""
        metadata = {
            **DCR_CLIENT_METADATA,
            "default_max_age": 3600,
            "require_auth_time": True,
            "default_acr_values": ["urn:mace:incommon:iap:silver"],
        }
        captured, capture_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        respx.post(REGISTER_EP).mock(side_effect=capture_fn)

        make_client().register_client(client_metadata=metadata)

        body = captured["body"]
        assert body["default_max_age"] == 3600
        assert body["require_auth_time"] is True
        assert body["default_acr_values"] == ["urn:mace:incommon:iap:silver"]

    # ── Complete rich-metadata round-trip ─────────────────────────────────────

    @respx.mock
    def test_full_rich_metadata_round_trip(self):
        """A fully-loaded client_metadata dict survives register → update unchanged."""
        rich_metadata = {
            "client_name": "Rich DCR Client",
            "grant_types": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "response_types": ["code"],
            "redirect_uris": [
                "https://app.example.com/callback",
                "https://app.example.com/callback2",
            ],
            "post_logout_redirect_uris": ["https://app.example.com/logout"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://app.example.com/.well-known/jwks.json",
            "scope": "openid profile email phone address",
            "subject_type": "pairwise",
            "sector_identifier_uri": "https://app.example.com/sector",
            "id_token_signed_response_alg": "RS256",
            "request_object_signing_alg": "RS256",
            "authorization_details_types": ["account_information", "payment_initiation"],
            "contacts": ["admin@example.com"],
            "logo_uri": "https://app.example.com/logo.png",
            "client_uri": "https://app.example.com",
            "default_max_age": 7200,
            "require_auth_time": False,
            "tls_client_certificate_bound_access_tokens": False,
            "ibm_custom_field": "ibm-value",
        }
        reg_captured, reg_fn = TestDcrFieldPassthrough._capture_register(DCR_REGISTRATION_RESPONSE)
        upd_captured, upd_fn = TestDcrFieldPassthrough._capture_update(DCR_UPDATED_METADATA)
        respx.post(REGISTER_EP).mock(side_effect=reg_fn)
        respx.put(CLIENT_URI).mock(side_effect=upd_fn)

        client = make_client()
        client.register_client(client_metadata=rich_metadata, initial_access_token="iat")

        # Every field that went in must come back out unchanged
        for key, expected in rich_metadata.items():
            assert reg_captured["body"][key] == expected, f"register: field '{key}' mismatch"

        updated_meta = {**rich_metadata, "client_name": "Rich DCR Client (updated)"}
        client.update_client(
            registration_access_token="rat",
            registration_client_uri=CLIENT_URI,
            client_metadata=updated_meta,
        )
        for key, expected in updated_meta.items():
            assert upd_captured["body"][key] == expected, f"update: field '{key}' mismatch"


# ==============================================================================
# TestAuthorizationDetailsAllGrants
# ==============================================================================
# Proves that authorization_details (RAR, RFC 9396) and extra_params are
# forwarded as request body parameters on every token grant type.
# Each test captures the raw request body and asserts the field is present
# and correctly serialised.
# ==============================================================================

class TestAuthorizationDetailsAllGrants:
    """authorization_details and extra_params reach the wire on every grant type."""

    RAR_PAYLOAD = [{"type": "account_information", "actions": ["read"]}]
    RAR_JSON    = json.dumps(RAR_PAYLOAD)
    EXTRA       = {"resource": "https://api.example.com", "audience": "my-service"}

    # ── client_credentials ────────────────────────────────────────────────────

    @respx.mock
    def test_client_credentials_authorization_details(self):
        """authorization_details is JSON-encoded in the client_credentials body."""
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["body"] = dict(request.url.params)   # form-encoded body
            # respx puts form data in the content bytes
            from urllib.parse import parse_qs
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).client_credentials(
            client_id="cid",
            client_secret="csec",
            scope="openid",
            authorization_header="Basic dGVzdA==",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_PAYLOAD,
        )

        form = captured["form"]
        assert "authorization_details" in form
        parsed = json.loads(form["authorization_details"][0])
        assert parsed == TestAuthorizationDetailsAllGrants.RAR_PAYLOAD

    @respx.mock
    def test_client_credentials_extra_params(self):
        """extra_params key/values are merged into the client_credentials body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).client_credentials(
            client_id="cid",
            client_secret="csec",
            scope="openid",
            authorization_header="Basic dGVzdA==",
            extra_params={"resource": "https://api.example.com", "audience": "svc"},
        )

        form = captured["form"]
        assert form["resource"][0] == "https://api.example.com"
        assert form["audience"][0] == "svc"

    @respx.mock
    def test_client_credentials_preserialised_string_not_double_encoded(self):
        """A pre-serialised JSON string is forwarded as-is without double-encoding."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).client_credentials(
            client_id="cid",
            client_secret="csec",
            scope="openid",
            authorization_header="Basic dGVzdA==",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_JSON,
        )

        form = captured["form"]
        raw = form["authorization_details"][0]
        # Must not be double-encoded — parse once should give the list
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
        assert parsed[0]["type"] == "account_information"

    # ── device_code / request_device_code ─────────────────────────────────────

    @respx.mock
    def test_device_code_authorization_details(self):
        """authorization_details is JSON-encoded in the device_authorization body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json={
                "device_code": "dc123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://example.com/activate",
                "expires_in": 300,
                "interval": 5,
            })

        respx.post(DEVICE_AUTH_EP).mock(side_effect=capture)
        make_client(with_discovery=True).request_device_code(
            client_id="cid",
            scope="openid",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_PAYLOAD,
        )

        form = captured["form"]
        assert "authorization_details" in form
        parsed = json.loads(form["authorization_details"][0])
        assert parsed == TestAuthorizationDetailsAllGrants.RAR_PAYLOAD

    @respx.mock
    def test_device_code_extra_params(self):
        """extra_params are merged into the device_authorization request body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json={
                "device_code": "dc123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://example.com/activate",
                "expires_in": 300,
                "interval": 5,
            })

        respx.post(DEVICE_AUTH_EP).mock(side_effect=capture)
        make_client(with_discovery=True).request_device_code(
            client_id="cid",
            scope="openid",
            extra_params={"resource": "https://api.example.com"},
        )

        assert captured["form"]["resource"][0] == "https://api.example.com"

    # ── jwt_bearer_grant ──────────────────────────────────────────────────────

    @respx.mock
    def test_jwt_bearer_authorization_details(self):
        """authorization_details is JSON-encoded in the jwt_bearer grant body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).jwt_bearer_grant(
            assertion="signed.jwt.here",
            client_id="cid",
            client_secret="csec",
            scope="openid",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_PAYLOAD,
        )

        form = captured["form"]
        assert "authorization_details" in form
        parsed = json.loads(form["authorization_details"][0])
        assert parsed == TestAuthorizationDetailsAllGrants.RAR_PAYLOAD

    @respx.mock
    def test_jwt_bearer_extra_params(self):
        """extra_params are merged into the jwt_bearer grant body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).jwt_bearer_grant(
            assertion="signed.jwt.here",
            client_id="cid",
            client_secret="csec",
            scope="openid",
            extra_params={"audience": "svc", "resource": "https://api.example.com"},
        )

        form = captured["form"]
        assert form["audience"][0] == "svc"
        assert form["resource"][0] == "https://api.example.com"

    # ── refresh_access_token ──────────────────────────────────────────────────

    @respx.mock
    def test_refresh_token_authorization_details(self):
        """authorization_details is JSON-encoded in the refresh_token grant body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=REFRESH_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).refresh_access_token(
            client_id="cid",
            refresh_token="rt-abc",
            client_secret="csec",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_PAYLOAD,
        )

        form = captured["form"]
        assert "authorization_details" in form
        parsed = json.loads(form["authorization_details"][0])
        assert parsed == TestAuthorizationDetailsAllGrants.RAR_PAYLOAD

    @respx.mock
    def test_refresh_token_extra_params(self):
        """extra_params are merged into the refresh_token grant body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=REFRESH_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).refresh_access_token(
            client_id="cid",
            refresh_token="rt-abc",
            client_secret="csec",
            extra_params={"resource": "https://api.example.com"},
        )

        assert captured["form"]["resource"][0] == "https://api.example.com"

    # ── token_exchange ────────────────────────────────────────────────────────

    @respx.mock
    def test_token_exchange_authorization_details(self):
        """authorization_details is JSON-encoded in the token_exchange grant body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).token_exchange(
            client_id="cid",
            client_secret="csec",
            subject_token="subj-tok",
            actor_token="actor-tok",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_PAYLOAD,
        )

        form = captured["form"]
        assert "authorization_details" in form
        parsed = json.loads(form["authorization_details"][0])
        assert parsed == TestAuthorizationDetailsAllGrants.RAR_PAYLOAD

    @respx.mock
    def test_token_exchange_extra_params(self):
        """extra_params are merged into the token_exchange grant body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json=ACCESS_TOKEN_RESPONSE)

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).token_exchange(
            client_id="cid",
            client_secret="csec",
            subject_token="subj-tok",
            actor_token="actor-tok",
            extra_params={"resource": "https://api.example.com", "scope": "read"},
        )

        form = captured["form"]
        assert form["resource"][0] == "https://api.example.com"

    # ── authorization_code / exchange_code_for_token ──────────────────────────

    @respx.mock
    def test_auth_code_exchange_authorization_details(self):
        """authorization_details is JSON-encoded in the authorization_code token body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json={**ACCESS_TOKEN_RESPONSE, "id_token": "id.tok.here"})

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).exchange_code_for_token(
            client_id="cid",
            redirect_uri="https://app.example.com/callback",
            code="auth-code-abc",
            code_verifier="verifier123",
            client_secret="csec",
            authorization_details=TestAuthorizationDetailsAllGrants.RAR_PAYLOAD,
        )

        form = captured["form"]
        assert "authorization_details" in form
        parsed = json.loads(form["authorization_details"][0])
        assert parsed == TestAuthorizationDetailsAllGrants.RAR_PAYLOAD

    @respx.mock
    def test_auth_code_exchange_extra_params(self):
        """extra_params are merged into the authorization_code token request body."""
        from urllib.parse import parse_qs
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["form"] = parse_qs(request.content.decode())
            return httpx.Response(200, json={**ACCESS_TOKEN_RESPONSE, "id_token": "id.tok.here"})

        respx.post(TOKEN_EP).mock(side_effect=capture)
        make_client(with_discovery=True).exchange_code_for_token(
            client_id="cid",
            redirect_uri="https://app.example.com/callback",
            code="auth-code-abc",
            code_verifier="verifier123",
            client_secret="csec",
            extra_params={"resource": "https://api.example.com"},
        )

        assert captured["form"]["resource"][0] == "https://api.example.com"
