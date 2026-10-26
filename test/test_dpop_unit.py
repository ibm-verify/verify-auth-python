# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for DPoP support (RFC 9449).

All network calls are mocked with respx so no live tenant is needed.
"""

import base64
import hashlib
import json
import time

import httpx
import pytest
import respx
from authlib.jose import JsonWebKey, jwt

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors.errors import VerifyError
from ibm_verify.oauth2.grant_types.dpop import (
    build_dpop_headers,
    compute_ath,
    compute_jkt,
    generate_dpop_key_pair,
    generate_dpop_proof,
    verify_dpop_proof,
)

BASE = "https://tenant.example.com"
TOKEN_EP = f"{BASE}/oauth2/token"
INTROSPECT_EP = f"{BASE}/oauth2/introspect"
RESOURCE_URL = "https://api.example.com/resource"

DPOP_TOKEN_RESPONSE = {
    "access_token": "dpop-access-token",
    "token_type": "DPoP",
    "expires_in": 3600,
    "scope": "openid",
    "refresh_token": "dpop-refresh-token",
}


@pytest.fixture(scope="module")
def rsa_key() -> str:
    return generate_dpop_key_pair("RSA")


@pytest.fixture(scope="module")
def ec_key() -> str:
    return generate_dpop_key_pair("EC")


def _decode_segment(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _parts(proof: str) -> tuple[dict, dict]:
    header, payload, _ = proof.split(".")
    return _decode_segment(header), _decode_segment(payload)


# ══════════════════════════════════════════════════════════════════════════════
# Key generation, thumbprint, ath
# ══════════════════════════════════════════════════════════════════════════════


class TestKeysAndThumbprint:
    def test_rsa_default(self, rsa_key):
        assert "BEGIN PRIVATE KEY" in rsa_key
        assert JsonWebKey.import_key(rsa_key).kty == "RSA"

    def test_ec(self, ec_key):
        assert JsonWebKey.import_key(ec_key).kty == "EC"

    def test_invalid_key_type(self):
        with pytest.raises(ValueError):
            generate_dpop_key_pair("DSA")

    def test_jkt_matches_rfc7638_vector(self):
        """RFC 7638 §3.1 example key and thumbprint."""
        jwk = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
                "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
                "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f"
                "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
        }
        key = JsonWebKey.import_key(jwk)
        assert key.thumbprint() == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    def test_jkt_stable_and_distinct(self, rsa_key, ec_key):
        assert compute_jkt(rsa_key) == compute_jkt(rsa_key)
        assert compute_jkt(rsa_key) != compute_jkt(ec_key)

    def test_ath(self):
        expected = base64.urlsafe_b64encode(hashlib.sha256(b"tok").digest()).rstrip(b"=").decode()
        assert compute_ath("tok") == expected


# ══════════════════════════════════════════════════════════════════════════════
# generate_dpop_proof
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateProof:
    def test_rsa_structure(self, rsa_key):
        proof = generate_dpop_proof(rsa_key, "post", TOKEN_EP)
        header, payload = _parts(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "RS256"
        assert set(header["jwk"]) == {"kty", "n", "e"}  # public members only
        assert payload["htm"] == "POST"
        assert payload["htu"] == TOKEN_EP
        assert payload["jti"]
        assert abs(payload["iat"] - int(time.time())) < 5
        assert "ath" not in payload and "nonce" not in payload

    def test_ec_structure(self, ec_key):
        header, _ = _parts(generate_dpop_proof(ec_key, "POST", TOKEN_EP))
        assert header["alg"] == "ES256"
        assert set(header["jwk"]) == {"kty", "crv", "x", "y"}

    def test_never_leaks_private_material(self, rsa_key):
        header, _ = _parts(generate_dpop_proof(rsa_key, "POST", TOKEN_EP))
        assert not {"d", "p", "q", "dp", "dq", "qi"} & set(header["jwk"])

    def test_htu_strips_query_and_fragment(self, rsa_key):
        _, payload = _parts(generate_dpop_proof(rsa_key, "GET", f"{RESOURCE_URL}?a=1#frag"))
        assert payload["htu"] == RESOURCE_URL

    def test_ath_and_nonce(self, rsa_key):
        _, payload = _parts(
            generate_dpop_proof(rsa_key, "GET", RESOURCE_URL, access_token="tok", nonce="n1")
        )
        assert payload["ath"] == compute_ath("tok")
        assert payload["nonce"] == "n1"

    def test_unique_jti(self, rsa_key):
        a = _parts(generate_dpop_proof(rsa_key, "POST", TOKEN_EP))[1]["jti"]
        b = _parts(generate_dpop_proof(rsa_key, "POST", TOKEN_EP))[1]["jti"]
        assert a != b

    def test_explicit_algorithm(self, rsa_key):
        header, _ = _parts(generate_dpop_proof(rsa_key, "POST", TOKEN_EP, algorithm="PS256"))
        assert header["alg"] == "PS256"

    def test_symmetric_algorithm_rejected(self, rsa_key):
        with pytest.raises(ValueError):
            generate_dpop_proof(rsa_key, "POST", TOKEN_EP, algorithm="HS256")

    def test_invalid_key(self):
        with pytest.raises(ValueError):
            generate_dpop_proof("not-a-key", "POST", TOKEN_EP)


# ══════════════════════════════════════════════════════════════════════════════
# build_dpop_headers / verify_dpop_proof
# ══════════════════════════════════════════════════════════════════════════════


class TestHeadersAndVerify:
    def test_headers_shape(self, rsa_key):
        headers = build_dpop_headers("tok", rsa_key, "GET", RESOURCE_URL)
        assert headers["Authorization"] == "DPoP tok"
        assert _parts(headers["DPoP"])[1]["ath"] == compute_ath("tok")

    @pytest.mark.parametrize("fixture", ["rsa_key", "ec_key"])
    def test_verify_valid(self, request, fixture):
        key = request.getfixturevalue(fixture)
        headers = build_dpop_headers("tok", key, "GET", RESOURCE_URL)
        payload = verify_dpop_proof(
            headers["DPoP"], "GET", f"{RESOURCE_URL}?x=1", "tok", compute_jkt(key)
        )
        assert payload["htm"] == "GET"

    def _proof(self, key):
        return build_dpop_headers("tok", key, "GET", RESOURCE_URL)["DPoP"]

    def test_wrong_method(self, rsa_key):
        with pytest.raises(ValueError, match="htm"):
            verify_dpop_proof(self._proof(rsa_key), "POST", RESOURCE_URL, "tok")

    def test_wrong_url(self, rsa_key):
        with pytest.raises(ValueError, match="htu"):
            verify_dpop_proof(self._proof(rsa_key), "GET", "https://evil.example.com/x", "tok")

    def test_wrong_ath(self, rsa_key):
        with pytest.raises(ValueError, match="ath"):
            verify_dpop_proof(self._proof(rsa_key), "GET", RESOURCE_URL, "other-token")

    def test_wrong_jkt(self, rsa_key, ec_key):
        with pytest.raises(ValueError, match="cnf.jkt"):
            verify_dpop_proof(self._proof(rsa_key), "GET", RESOURCE_URL, "tok", compute_jkt(ec_key))

    def test_tampered_signature(self, rsa_key):
        proof = self._proof(rsa_key)
        header, payload, sig = proof.split(".")
        forged = ".".join([header, payload, "A" * len(sig)])
        with pytest.raises(ValueError, match="signature"):
            verify_dpop_proof(forged, "GET", RESOURCE_URL, "tok")

    def test_tampered_payload(self, rsa_key):
        proof = self._proof(rsa_key)
        header, payload, sig = proof.split(".")
        body = _decode_segment(payload)
        body["htm"] = "DELETE"
        new_payload = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
        with pytest.raises(ValueError, match="signature"):
            verify_dpop_proof(".".join([header, new_payload, sig]), "DELETE", RESOURCE_URL)

    def test_expired_proof(self, rsa_key):
        key = JsonWebKey.import_key(rsa_key)
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": key.as_dict(is_private=False),
        }
        claims = {
            "jti": "x",
            "iat": int(time.time()) - 3600,
            "htm": "GET",
            "htu": RESOURCE_URL,
        }
        proof = jwt.encode(header, claims, key).decode()
        with pytest.raises(ValueError, match="expired"):
            verify_dpop_proof(proof, "GET", RESOURCE_URL)

    def test_wrong_typ(self, rsa_key):
        key = JsonWebKey.import_key(rsa_key)
        header = {"typ": "JWT", "alg": "RS256", "jwk": key.as_dict(is_private=False)}
        claims = {"jti": "x", "iat": int(time.time()), "htm": "GET", "htu": RESOURCE_URL}
        proof = jwt.encode(header, claims, key).decode()
        with pytest.raises(ValueError, match="typ"):
            verify_dpop_proof(proof, "GET", RESOURCE_URL)

    def test_private_jwk_in_header_rejected(self, rsa_key):
        key = JsonWebKey.import_key(rsa_key)
        header = {"typ": "dpop+jwt", "alg": "RS256", "jwk": key.as_dict(is_private=True)}
        claims = {"jti": "x", "iat": int(time.time()), "htm": "GET", "htu": RESOURCE_URL}
        proof = jwt.encode(header, claims, key).decode()
        with pytest.raises(ValueError, match="private"):
            verify_dpop_proof(proof, "GET", RESOURCE_URL)

    def test_garbage(self):
        with pytest.raises(ValueError):
            verify_dpop_proof("not.a.jwt", "GET", RESOURCE_URL)


# ══════════════════════════════════════════════════════════════════════════════
# Token requests carry the DPoP header
# ══════════════════════════════════════════════════════════════════════════════


def _capture(captured: dict, body: dict = DPOP_TOKEN_RESPONSE):
    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["body"] = request.content.decode()
        return httpx.Response(200, json=body)

    return handler


def _assert_token_proof(captured: dict, key: str) -> None:
    proof = captured["headers"]["dpop"]
    header, payload = _parts(proof)
    assert header["typ"] == "dpop+jwt"
    assert payload["htm"] == "POST"
    assert payload["htu"] == TOKEN_EP
    assert "ath" not in payload
    # Proof must verify and be bound to our key
    verify_dpop_proof(proof, "POST", TOKEN_EP, expected_jkt=compute_jkt(key))


class TestTokenRequests:
    @respx.mock
    def test_client_credentials_sends_dpop(self, rsa_key):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        token = OAuthClient(base_url=BASE).client_credentials(
            client_id="c",
            client_secret="s",
            scope="openid",
            authorization_header="Basic abc",
            dpop_private_key=rsa_key,
        )
        assert token["token_type"] == "DPoP"
        assert captured["headers"]["authorization"].startswith("Basic ")
        _assert_token_proof(captured, rsa_key)

    @respx.mock
    def test_client_credentials_without_key_sends_no_dpop(self):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        OAuthClient(base_url=BASE).client_credentials(
            client_id="c", client_secret="s", scope="openid", authorization_header="Basic abc"
        )
        assert "dpop" not in captured["headers"]

    @respx.mock
    def test_client_credentials_nonce_and_algorithm(self, rsa_key):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        OAuthClient(base_url=BASE).client_credentials(
            client_id="c",
            client_secret="s",
            scope="openid",
            authorization_header="Basic abc",
            dpop_private_key=rsa_key,
            dpop_nonce="server-nonce",
            dpop_algorithm="PS256",
        )
        header, payload = _parts(captured["headers"]["dpop"])
        assert header["alg"] == "PS256"
        assert payload["nonce"] == "server-nonce"

    @respx.mock
    @pytest.mark.parametrize("auth", ["secret", "public", "assertion"])
    def test_authorization_code_sends_dpop(self, rsa_key, auth):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        kwargs: dict = {}
        if auth == "secret":
            kwargs["client_secret"] = "s"
        elif auth == "assertion":
            kwargs["client_assertion"] = "a.b.c"
        token = OAuthClient(base_url=BASE).exchange_code_for_token(
            client_id="c",
            redirect_uri="http://localhost/cb",
            code="code1",
            code_verifier="v" * 43,
            dpop_private_key=rsa_key,
            **kwargs,
        )
        assert token["token_type"] == "DPoP"
        assert "code=code1" in captured["body"]
        _assert_token_proof(captured, rsa_key)

    @respx.mock
    def test_authorization_code_without_key_sends_no_dpop(self):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        OAuthClient(base_url=BASE).exchange_code_for_token(
            client_id="c", redirect_uri="http://localhost/cb", code="x", code_verifier="v" * 43
        )
        assert "dpop" not in captured["headers"]

    @respx.mock
    @pytest.mark.parametrize("auth", ["secret", "public", "assertion"])
    def test_refresh_token_sends_dpop(self, rsa_key, auth):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        kwargs: dict = {}
        if auth == "secret":
            kwargs["client_secret"] = "s"
        elif auth == "assertion":
            kwargs["client_assertion"] = "a.b.c"
        token = OAuthClient(base_url=BASE).refresh_access_token(
            client_id="c", refresh_token="rt", dpop_private_key=rsa_key, **kwargs
        )
        assert token["token_type"] == "DPoP"
        assert "refresh_token=rt" in captured["body"]
        _assert_token_proof(captured, rsa_key)

    @respx.mock
    def test_refresh_token_without_key_sends_no_dpop(self):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(side_effect=_capture(captured))
        OAuthClient(base_url=BASE).refresh_access_token(client_id="c", refresh_token="rt")
        assert "dpop" not in captured["headers"]

    @respx.mock
    def test_proof_targets_resolved_custom_endpoint(self, rsa_key):
        custom = "https://custom.example.com/token"
        captured: dict = {}
        respx.post(custom).mock(side_effect=_capture(captured))
        OAuthClient(base_url=BASE).client_credentials(
            client_id="c",
            client_secret="s",
            scope="openid",
            authorization_header="Basic abc",
            token_endpoint=custom,
            dpop_private_key=rsa_key,
        )
        assert _parts(captured["headers"]["dpop"])[1]["htu"] == custom

    @respx.mock
    def test_warns_when_server_returns_bearer(self, rsa_key, caplog):
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(200, json={**DPOP_TOKEN_RESPONSE, "token_type": "Bearer"})
        )
        with caplog.at_level("WARNING"):
            OAuthClient(base_url=BASE).client_credentials(
                client_id="c",
                client_secret="s",
                scope="openid",
                authorization_header="Basic abc",
                dpop_private_key=rsa_key,
            )
        assert "not DPoP-bound" in caplog.text

    @respx.mock
    def test_server_error_raises_verify_error(self, rsa_key):
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(
                400, json={"error": "invalid_dpop_proof", "error_description": "bad proof"}
            )
        )
        with pytest.raises(VerifyError) as exc_info:
            OAuthClient(base_url=BASE).client_credentials(
                client_id="c",
                client_secret="s",
                scope="openid",
                authorization_header="Basic abc",
                dpop_private_key=rsa_key,
            )
        assert exc_info.value.error == "invalid_dpop_proof"


# ══════════════════════════════════════════════════════════════════════════════
# OAuthClient static helpers + introspect_dpop_token
# ══════════════════════════════════════════════════════════════════════════════


class TestClientHelpers:
    def test_static_helpers_available_on_client(self, rsa_key):
        key = OAuthClient.generate_dpop_key_pair("EC")
        assert JsonWebKey.import_key(key).kty == "EC"
        assert OAuthClient.compute_dpop_jkt(rsa_key) == compute_jkt(rsa_key)
        headers = OAuthClient.build_dpop_headers("tok", rsa_key, "GET", RESOURCE_URL)
        assert headers["Authorization"] == "DPoP tok"
        proof = OAuthClient.generate_dpop_proof(rsa_key, "GET", RESOURCE_URL, access_token="tok")
        verify_dpop_proof(proof, "GET", RESOURCE_URL, "tok")


class TestIntrospectDPoP:
    def _introspect(self, key, active_body, proof=None, method="GET", url=RESOURCE_URL):
        proof = proof or build_dpop_headers("tok", key, "GET", RESOURCE_URL)["DPoP"]
        with respx.mock:
            respx.post(INTROSPECT_EP).mock(return_value=httpx.Response(200, json=active_body))
            return OAuthClient(base_url=BASE).introspect_dpop_token(
                token="tok",
                dpop_proof=proof,
                http_method=method,
                http_url=url,
                client_id="c",
                client_secret="s",
            )

    def test_valid(self, rsa_key):
        body = {"active": True, "token_type": "DPoP", "cnf": {"jkt": compute_jkt(rsa_key)}}
        assert self._introspect(rsa_key, body)["active"] is True

    def test_jkt_mismatch(self, rsa_key, ec_key):
        body = {"active": True, "cnf": {"jkt": compute_jkt(ec_key)}}
        with pytest.raises(VerifyError) as exc_info:
            self._introspect(rsa_key, body)
        assert exc_info.value.error == "invalid_dpop_proof"

    def test_not_dpop_bound(self, rsa_key):
        with pytest.raises(VerifyError, match="not DPoP-bound"):
            self._introspect(rsa_key, {"active": True})

    def test_htm_mismatch(self, rsa_key):
        body = {"active": True, "cnf": {"jkt": compute_jkt(rsa_key)}}
        with pytest.raises(VerifyError):
            self._introspect(rsa_key, body, method="POST")

    def test_htu_mismatch(self, rsa_key):
        body = {"active": True, "cnf": {"jkt": compute_jkt(rsa_key)}}
        with pytest.raises(VerifyError):
            self._introspect(rsa_key, body, url="https://other.example.com/x")

    def test_ath_mismatch(self, rsa_key):
        body = {"active": True, "cnf": {"jkt": compute_jkt(rsa_key)}}
        wrong = build_dpop_headers("different-token", rsa_key, "GET", RESOURCE_URL)["DPoP"]
        with pytest.raises(VerifyError):
            self._introspect(rsa_key, body, proof=wrong)

    def test_inactive_returned_as_is(self, rsa_key):
        assert self._introspect(rsa_key, {"active": False}) == {"active": False}
