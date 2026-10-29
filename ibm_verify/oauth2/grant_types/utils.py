# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — shared utility functions.

Stateless helpers used by multiple grant modules:
- PKCE code_verifier / code_challenge generation (RFC 7636)
- JWT client assertion building (private_key_jwt, RFC 7523)
- JWT bearer assertion building (jwt-bearer grant, RFC 7523)
"""

import base64
import hashlib
import secrets
import time
import uuid
from typing import Any, Optional, Union

from ibm_verify.oauth2.grant_types.constants import (
    JWT_BEARER_ASSERTION_EXPIRES_IN,
    JWT_CLIENT_ASSERTION_EXPIRES_IN,
    JWT_DEFAULT_ALGORITHM,
    PKCE_CHALLENGE_METHOD,
    PKCE_VERIFIER_BYTE_LENGTH,
)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE ``(code_verifier, code_challenge)`` pair using S256.

    Returns:
        ``(code_verifier, code_challenge)`` — both URL-safe base64 strings.

    Example::

        verifier, challenge = generate_pkce_pair()
        url = build_authorization_url(..., code_challenge=challenge)
        token = exchange_code_for_token(..., code_verifier=verifier)
    """
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(PKCE_VERIFIER_BYTE_LENGTH))
        .rstrip(b"=")
        .decode()
    )
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


def build_authorization_url(
    authorize_endpoint: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    scope: str = "openid profile email",
    state: Optional[str] = None,
    nonce: Optional[str] = None,
    authorization_details: Optional[Any] = None,
    extra_params: Optional[dict[str, Any]] = None,
    dpop_jkt: Optional[str] = None,
) -> str:
    """Build an Authorization Code + PKCE redirect URL (RFC 7636).

    Args:
        authorize_endpoint: Full authorization endpoint URL.
        client_id: OAuth client ID.
        redirect_uri: Redirect URI registered with IBM Verify.
        code_challenge: S256 code challenge from :func:`generate_pkce_pair`.
        scope: Space-separated scopes (default: ``"openid profile email"``).
        state: CSRF protection value — auto-generated if omitted.
        nonce: Optional nonce for ID-token replay protection.
        authorization_details: Rich authorization request object (RAR, RFC 9396).
            Encoded as a JSON string in the query parameter.
        extra_params: Additional query parameters to include in the URL.
        dpop_jkt: DPoP key thumbprint (RFC 9449 §10) binding the authorization code
            to the client's DPoP key.

    Returns:
        Authorization URL to redirect the user's browser to.
    """
    import json
    from urllib.parse import urlencode

    if state is None:
        state = secrets.token_urlsafe(16)

    params: dict[str, Any] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": PKCE_CHALLENGE_METHOD,
    }
    if nonce:
        params["nonce"] = nonce
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    if authorization_details is not None:
        params["authorization_details"] = (
            json.dumps(authorization_details)
            if not isinstance(authorization_details, str)
            else authorization_details
        )
    if extra_params:
        params.update(extra_params)

    return f"{authorize_endpoint}?{urlencode(params)}"


def generate_client_assertion_jwt(
    client_id: str,
    token_endpoint: str,
    private_key: str,
    algorithm: str = JWT_DEFAULT_ALGORITHM,
    expires_in: int = JWT_CLIENT_ASSERTION_EXPIRES_IN,
    key_id: Optional[str] = None,
    audience: Optional[Union[str, list[str]]] = None,
) -> str:
    """Generate a signed JWT for ``private_key_jwt`` client authentication (RFC 7523).

    The resulting JWT is passed as ``client_assertion`` in token requests.
    The corresponding public key must be registered with IBM Verify.

    Args:
        client_id: OAuth client ID (used as both ``iss`` and ``sub``).
        token_endpoint: Token endpoint URL (used as ``aud``).
        private_key: PEM-encoded RSA or EC private key.
        algorithm: JWT signing algorithm (default: ``"RS256"``).
        expires_in: JWT lifetime in seconds (default: 300).
        key_id: Optional ``kid`` header to identify the registered key.
        audience: Explicit ``aud`` override — a string or a list. Defaults to
            ``token_endpoint``. IBM's Go SDK sends
            ``["https://<tenant>/oauth2", "https://<tenant>/oauth2/token"]``.

    Returns:
        Signed JWT string for use as ``client_assertion``.

    Raises:
        ValueError: If the private key is invalid or algorithm is unsupported.
    """
    from authlib.jose import jwt as authlib_jwt

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience or token_endpoint,
        "jti": str(uuid.uuid4()),
        "exp": now + expires_in,
        "iat": now,
    }
    header: dict[str, Any] = {"alg": algorithm, "typ": "JWT"}
    if key_id:
        header["kid"] = key_id

    try:
        token = authlib_jwt.encode(header=header, payload=claims, key=private_key)
        return token.decode() if isinstance(token, bytes) else token
    except Exception as exc:
        raise ValueError(f"Failed to generate JWT client assertion: {exc}") from exc


def generate_jwt_bearer_assertion(
    subject: str,
    token_endpoint: str,
    issuer: str,
    private_key: str,
    algorithm: str = JWT_DEFAULT_ALGORITHM,
    expires_in: int = JWT_BEARER_ASSERTION_EXPIRES_IN,
    audience: Optional[str] = None,
    additional_claims: Optional[dict[str, Any]] = None,
    key_id: Optional[str] = None,
) -> str:
    """Generate a signed JWT assertion for the JWT Bearer Grant (RFC 7523).

    IBM Verify resolves the signing key via the ``kid`` header, which must
    match the label of a certificate uploaded to **Security → Certificates**.

    Required claims: ``iss``, ``sub``, ``aud``, ``jti``, ``exp`` (≤ 5 min).
    Required header fields: ``alg``, ``typ=JWT``, ``kid`` (certificate label).

    Args:
        subject: Subject (``sub``) — typically a valid tenant username.
        token_endpoint: Token endpoint URL used as ``aud``.
        issuer: Entity issuing the JWT (``iss`` claim).
        private_key: PEM-encoded RSA or EC private key.
        algorithm: JWT signing algorithm (default: ``"RS256"``).
        expires_in: JWT lifetime in seconds (default: 300).
        audience: Explicit audience override (defaults to ``token_endpoint``).
        additional_claims: Extra claims to merge into the payload.
        key_id: ``kid`` header identifying the registered signing certificate.

    Returns:
        Signed JWT string for use as the ``assertion`` parameter.

    Raises:
        ValueError: If ``key_id`` is missing, or the key/algorithm is invalid.

    Example::

        with open("jwtbearer_private.pem") as f:
            private_key = f.read()

        assertion = generate_jwt_bearer_assertion(
            subject="alice@example.com",
            token_endpoint="https://tenant.verify.ibm.com/oauth2/token",
            issuer="https://tenant.verify.ibm.com",
            private_key=private_key,
            key_id="jwtbearer-cert-01",
        )
    """
    from authlib.jose import jwt as authlib_jwt

    if not key_id:
        raise ValueError(
            "key_id is required for IBM Verify JWT Bearer assertions. "
            "Set it to the certificate label shown on the certificate's "
            "Details page in Security → Certificates."
        )

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience or token_endpoint,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + expires_in,
    }
    if additional_claims:
        claims.update(additional_claims)

    header: dict[str, Any] = {"alg": algorithm}
    if key_id:
        header["kid"] = key_id

    try:
        token = authlib_jwt.encode(header=header, payload=claims, key=private_key)
        return token.decode() if isinstance(token, bytes) else token
    except Exception as exc:
        raise ValueError(f"Failed to generate JWT Bearer assertion: {exc}") from exc
