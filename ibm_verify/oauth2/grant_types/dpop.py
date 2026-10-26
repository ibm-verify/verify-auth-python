# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — DPoP helpers (RFC 9449).

Stateless helpers for Demonstrating Proof of Possession:
- key-pair generation (RSA or EC)
- DPoP proof JWT creation (``typ=dpop+jwt``)
- RFC 7638 JWK thumbprint (``cnf.jkt``)
- resource-request headers (``Authorization: DPoP <token>`` + ``DPoP: <proof>``)
- proof verification (signature, ``htm``/``htu``, ``ath``, ``cnf.jkt`` binding)

The private key never leaves the client.  Only the public JWK is embedded in
the proof header.
"""

import base64
import hashlib
import logging
import threading
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

from ibm_verify.oauth2.grant_types.constants import (
    DPOP_DEFAULT_KEY_TYPE,
    DPOP_JWT_TYPE,
    DPOP_PROOF_LEEWAY,
    DPOP_PROOF_MAX_AGE,
    TOKEN_TYPE_DPOP,
)

logger = logging.getLogger(__name__)

# Public members that may appear in a proof's ``jwk`` header, per key type.
_PUBLIC_JWK_MEMBERS = {
    "RSA": ("kty", "n", "e"),
    "EC": ("kty", "crv", "x", "y"),
    "OKP": ("kty", "crv", "x"),
}

_EC_CURVE_ALGORITHMS = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}

# Only asymmetric algorithms are acceptable for a DPoP proof.
_ALLOWED_PROOF_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
]


def _import_key(private_key: str) -> Any:
    from authlib.jose import JsonWebKey

    try:
        return JsonWebKey.import_key(private_key)
    except Exception as exc:
        raise ValueError(f"Invalid DPoP private key: {exc}") from exc


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _public_jwk(key: Any) -> dict[str, Any]:
    data = key.as_dict(is_private=False)
    members = _PUBLIC_JWK_MEMBERS.get(data.get("kty", ""))
    if members is None:
        raise ValueError(f"Unsupported DPoP key type: {data.get('kty')!r}")
    return {m: data[m] for m in members if m in data}


def _infer_algorithm(key: Any) -> str:
    data = key.as_dict(is_private=False)
    kty = data.get("kty")
    if kty == "RSA":
        return "RS256"
    if kty == "EC" and data.get("crv") in _EC_CURVE_ALGORITHMS:
        return _EC_CURVE_ALGORITHMS[data["crv"]]
    if kty == "OKP":
        return "EdDSA"
    raise ValueError(f"Unsupported DPoP key type/curve: {kty!r}/{data.get('crv')!r}")


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_htu(url: str) -> str:
    """Return ``url`` normalised for ``htu`` use (RFC 9449 §4.2 / §4.3).

    Query and fragment are removed, scheme and host are lower-cased, a default
    port (``:443`` for https, ``:80`` for http) is dropped and an empty path
    becomes ``/`` (RFC 3986 §6.2.2–6.2.3 syntax- and scheme-based normalisation).
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if parts.hostname and ":" in parts.hostname:  # IPv6 literal
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    if parts.username or parts.password:
        userinfo = parts.netloc.rsplit("@", 1)[0]
        netloc = f"{userinfo}@{netloc}"
    return f"{scheme}://{netloc}{parts.path or '/'}"


def dpop_origin(url: str) -> str:
    """Return ``scheme://host[:port]`` — the key under which a server's DPoP nonce is cached."""
    normalized = _normalize_htu(url)
    parts = urlsplit(normalized)
    return f"{parts.scheme}://{parts.netloc}"


def is_use_dpop_nonce_challenge(status_code: int, headers: Any, body: Any = None) -> bool:
    """Return True if a response asks the client to retry with a server nonce.

    Authorization servers answer ``400`` with ``{"error": "use_dpop_nonce"}``;
    resource servers answer ``401`` with ``WWW-Authenticate: DPoP error="use_dpop_nonce"``
    (RFC 9449 §8 and §9).  A ``DPoP-Nonce`` header must accompany either form.
    """
    if not headers.get("dpop-nonce"):
        return False
    if isinstance(body, dict) and body.get("error") == "use_dpop_nonce":
        return True
    www = headers.get("www-authenticate", "") or ""
    return status_code == 401 and "use_dpop_nonce" in www


class InMemoryDPoPReplayCache:
    """Thread-safe in-process ``jti`` replay cache for :func:`verify_dpop_proof`.

    RFC 9449 §11.1 requires a resource server to reject a proof whose ``jti``
    it has already seen within the acceptance window.  Entries expire after
    ``ttl`` seconds (use at least ``max_age + leeway``).  For multi-instance
    deployments, implement the same ``check_and_store`` method on a shared store
    such as Redis (``SET jti 1 NX EX ttl``).
    """

    def __init__(self, ttl: int = 0) -> None:
        self.ttl = ttl or (DPOP_PROOF_MAX_AGE + DPOP_PROOF_LEEWAY)
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_store(self, jti: str) -> bool:
        """Record ``jti``; return ``False`` if it was already present (a replay)."""
        now = time.time()
        with self._lock:
            if len(self._seen) > 1024:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            expiry = self._seen.get(jti)
            if expiry is not None and expiry > now:
                return False
            self._seen[jti] = now + self.ttl
            return True


def compute_ath(access_token: str) -> str:
    """Return the ``ath`` claim value: base64url(SHA-256(access_token))."""
    return _b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def generate_dpop_key_pair(key_type: str = DPOP_DEFAULT_KEY_TYPE, size_or_curve: Any = None) -> str:
    """Generate an asymmetric key pair for DPoP and return the private key as PEM.

    The caller must keep this private key and reuse it for every request that
    belongs to the same DPoP-bound token.

    Args:
        key_type: ``"RSA"`` (default, matches IBM Verify's default ``RS256``) or ``"EC"``.
        size_or_curve: RSA key size in bits (default 2048) or EC curve
            (default ``"P-256"``).

    Returns:
        PEM-encoded (PKCS#8) private key string.
    """
    from authlib.jose import JsonWebKey

    if key_type == "RSA":
        key = JsonWebKey.generate_key("RSA", size_or_curve or 2048, is_private=True)
    elif key_type == "EC":
        key = JsonWebKey.generate_key("EC", size_or_curve or "P-256", is_private=True)
    else:
        raise ValueError("key_type must be 'RSA' or 'EC'")
    pem = key.as_pem(is_private=True)
    return pem.decode() if isinstance(pem, bytes) else pem


def compute_jkt(private_key: str) -> str:
    """Return the RFC 7638 JWK SHA-256 thumbprint of the key (the ``cnf.jkt`` value).

    Args:
        private_key: PEM-encoded private (or public) key.
    """
    return str(_import_key(private_key).thumbprint())


def generate_dpop_proof(
    private_key: str,
    http_method: str,
    http_url: str,
    access_token: Optional[str] = None,
    nonce: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> str:
    """Create a signed DPoP proof JWT (RFC 9449 §4.2).

    A new proof must be created for every request.

    Args:
        private_key: PEM-encoded RSA or EC private key.
        http_method: HTTP method of the request the proof is for (``htm``).
        http_url: Target URL (``htu``). Query and fragment are removed.
        access_token: When calling a protected resource, the access token the
            proof is bound to — adds the ``ath`` claim. Omit for token requests.
        nonce: Server-provided ``DPoP-Nonce`` value, if the server demanded one.
        algorithm: JWS algorithm. Defaults to what the key implies
            (RSA → ``RS256``, P-256 → ``ES256``, …). Must match the
            "Signing algorithm for DPoP JWT" configured on the IBM Verify application.

    Returns:
        Compact-serialized proof JWT for the ``DPoP`` request header.

    Raises:
        ValueError: If the key or algorithm is invalid.
    """
    from authlib.jose import jwt as authlib_jwt

    key = _import_key(private_key)
    alg = algorithm or _infer_algorithm(key)
    if alg not in _ALLOWED_PROOF_ALGORITHMS:
        raise ValueError(f"Unsupported DPoP algorithm: {alg!r}")

    header: dict[str, Any] = {"typ": DPOP_JWT_TYPE, "alg": alg, "jwk": _public_jwk(key)}
    claims: dict[str, Any] = {
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "htm": http_method.upper(),
        "htu": _normalize_htu(http_url),
    }
    if access_token:
        claims["ath"] = compute_ath(access_token)
    if nonce:
        claims["nonce"] = nonce

    try:
        token = authlib_jwt.encode(header=header, payload=claims, key=key)
    except Exception as exc:
        raise ValueError(f"Failed to generate DPoP proof: {exc}") from exc
    return token.decode() if isinstance(token, bytes) else token


def build_dpop_headers(
    access_token: str,
    private_key: str,
    http_method: str,
    http_url: str,
    nonce: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> dict[str, str]:
    """Build the headers for a call to a DPoP-protected resource.

    Returns:
        ``{"Authorization": "DPoP <token>", "DPoP": "<fresh proof with ath>"}``.
    """
    proof = generate_dpop_proof(
        private_key=private_key,
        http_method=http_method,
        http_url=http_url,
        access_token=access_token,
        nonce=nonce,
        algorithm=algorithm,
    )
    return {"Authorization": f"{TOKEN_TYPE_DPOP} {access_token}", "DPoP": proof}


def verify_dpop_proof(
    proof: str,
    http_method: str,
    http_url: str,
    access_token: Optional[str] = None,
    expected_jkt: Optional[str] = None,
    max_age: int = DPOP_PROOF_MAX_AGE,
    leeway: int = DPOP_PROOF_LEEWAY,
    expected_nonce: Optional[str] = None,
    replay_cache: Optional[Any] = None,
) -> dict[str, Any]:
    """Verify a DPoP proof as a resource server / introspection consumer would.

    Checks: ``typ=dpop+jwt``; asymmetric ``alg``; signature against the embedded
    ``jwk`` (which must be public only); ``jti``/``iat`` present and fresh;
    ``htm``/``htu`` match the request (``htu`` compared after normalisation);
    ``ath`` matches ``access_token`` (when given); the ``jwk`` thumbprint equals
    ``expected_jkt`` (the ``cnf.jkt`` from introspection); ``nonce`` equals
    ``expected_nonce`` (when given); ``jti`` not seen before (when a
    ``replay_cache`` is given).

    Args:
        proof: The ``DPoP`` header value.
        http_method: Actual request method.
        http_url: Actual request URL (query/fragment ignored).
        access_token: Access token presented with the request.
        expected_jkt: ``cnf.jkt`` of the token (from introspection).
        max_age: Maximum proof age in seconds.
        leeway: Allowed clock skew into the future, in seconds.
        expected_nonce: Nonce this server issued via ``DPoP-Nonce``; the proof's
            ``nonce`` claim must equal it.
        replay_cache: Object with ``check_and_store(jti) -> bool`` (e.g.
            :class:`InMemoryDPoPReplayCache`). Without one, replays are NOT detected.

    Returns:
        The verified proof payload.

    Raises:
        ValueError: If any check fails.
    """
    import json

    from authlib.jose import JsonWebKey, JsonWebSignature

    jws = JsonWebSignature(algorithms=_ALLOWED_PROOF_ALGORITHMS)
    try:
        header_segment = proof.split(".")[0]
        header = json.loads(
            base64.urlsafe_b64decode(header_segment + "=" * (-len(header_segment) % 4))
        )
    except Exception as exc:
        raise ValueError(f"Malformed DPoP proof: {exc}") from exc
    if not isinstance(header, dict):
        raise ValueError("Malformed DPoP proof: header is not a JSON object")

    if header.get("typ") != DPOP_JWT_TYPE:
        raise ValueError(f"DPoP proof typ must be {DPOP_JWT_TYPE!r}")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ValueError("DPoP proof header is missing 'jwk'")
    if any(m in jwk for m in ("d", "p", "q", "dp", "dq", "qi", "k")):
        raise ValueError("DPoP proof 'jwk' must not contain private key material")

    try:
        public_key = JsonWebKey.import_key(jwk)
        decoded = jws.deserialize_compact(proof, public_key)
    except Exception as exc:
        raise ValueError(f"DPoP proof signature is invalid: {exc}") from exc

    try:
        payload = json.loads(decoded["payload"])
    except Exception as exc:
        raise ValueError(f"DPoP proof payload is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("DPoP proof payload is not a JSON object")
    jti = payload.get("jti")
    if not jti or not isinstance(jti, str):
        raise ValueError("DPoP proof is missing 'jti'")
    iat = payload.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        raise ValueError("DPoP proof is missing a numeric 'iat'")
    now = int(time.time())
    if iat > now + leeway:
        raise ValueError("DPoP proof 'iat' is in the future")
    if iat < now - max_age:
        raise ValueError("DPoP proof has expired")

    if str(payload.get("htm", "")).upper() != http_method.upper():
        raise ValueError("DPoP proof 'htm' does not match the request method")
    htu = payload.get("htu")
    if not isinstance(htu, str) or _normalize_htu(htu) != _normalize_htu(http_url):
        raise ValueError("DPoP proof 'htu' does not match the request URL")

    if access_token is not None and payload.get("ath") != compute_ath(access_token):
        raise ValueError("DPoP proof 'ath' does not match the access token")

    if expected_jkt is not None and public_key.thumbprint() != expected_jkt:
        raise ValueError("DPoP proof key thumbprint does not match cnf.jkt")

    if expected_nonce is not None and payload.get("nonce") != expected_nonce:
        raise ValueError("DPoP proof 'nonce' is missing or does not match")

    # Replay check last, so a proof that fails other checks doesn't consume its jti.
    if replay_cache is not None and not replay_cache.check_and_store(jti):
        raise ValueError("DPoP proof 'jti' has already been used (replay)")

    return payload


def build_token_request_dpop_header(
    private_key: str,
    token_endpoint: str,
    nonce: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> dict[str, str]:
    """Return ``{"DPoP": <proof>}`` for a ``POST`` to the token endpoint."""
    return {
        "DPoP": generate_dpop_proof(
            private_key=private_key,
            http_method="POST",
            http_url=token_endpoint,
            nonce=nonce,
            algorithm=algorithm,
        )
    }


def warn_if_not_dpop_token(token: dict[str, Any]) -> None:
    """Log a warning if a DPoP proof was sent but the server did not issue a DPoP token."""
    token_type = str(token.get("token_type", ""))
    if token_type.lower() != TOKEN_TYPE_DPOP.lower():
        logger.warning(
            "DPoP proof was sent but the server returned token_type=%r; "
            "the access token is not DPoP-bound.",
            token_type,
        )
