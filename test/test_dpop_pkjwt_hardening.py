# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for DPoP nonce handling, verifier hardening and private_key_jwt.

Covers:
- ``use_dpop_nonce`` auto-retry at the token endpoint, nonce caching, and
  ``VerifyError.dpop_nonce`` when the challenge persists (RFC 9449 §8)
- ``dpop_request()`` resource calls with the 401 nonce challenge (RFC 9449 §9)
- ``verify_dpop_proof``: htu normalisation, fractional ``iat``, ``expected_nonce``,
  ``jti`` replay cache
- DPoP on every token-endpoint grant
- ``private_key_jwt`` on client_credentials and introspection (RFC 7523 §2.2)

All network calls are mocked with respx.
"""

import base64
import json
import time
import uuid
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from authlib.jose import JsonWebKey, jwt

from ibm_verify.oauth2.auth.client import OAuthClient
from ibm_verify.oauth2.core.errors.errors import VerifyError
from ibm_verify.oauth2.grant_types.constants import CLIENT_ASSERTION_TYPE_JWT
from ibm_verify.oauth2.grant_types.dpop import (
    InMemoryDPoPReplayCache,
    _normalize_htu,
    _public_jwk,
    compute_ath,
    compute_jkt,
    generate_dpop_key_pair,
    generate_dpop_proof,
    verify_dpop_proof,
)
from ibm_verify.oauth2.grant_types.utils import (
    build_authorization_url,
    generate_client_assertion_jwt,
)

BASE = "https://tenant.example.com"
TOKEN_EP = f"{BASE}/oauth2/token"
INTROSPECT_EP = f"{BASE}/oauth2/introspect"
RESOURCE = "https://api.example.com/photos"
DPOP_TOKEN = {"access_token": "at", "token_type": "DPoP", "expires_in": 3600}


@pytest.fixture(scope="module")
def key() -> str:
    return generate_dpop_key_pair("RSA")


def _payload(proof: str) -> dict:
    seg = proof.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _form(request: httpx.Request) -> dict:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def _hand_proof(key_pem: str, **claims) -> str:
    k = JsonWebKey.import_key(key_pem)
    payload = {"jti": str(uuid.uuid4()), "iat": int(time.time()), "htm": "GET", "htu": RESOURCE}
    payload.update(claims)
    token = jwt.encode({"typ": "dpop+jwt", "alg": "RS256", "jwk": _public_jwk(k)}, payload, k)
    return token.decode()


# ══════════════════════════════════════════════════════════════════════════════
# Token endpoint nonce handling
# ══════════════════════════════════════════════════════════════════════════════


class TestTokenEndpointNonce:
    @respx.mock
    def test_use_dpop_nonce_is_retried_with_server_nonce(self, key):
        seen: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonce = _payload(request.headers["dpop"]).get("nonce")
            seen.append(nonce)
            if nonce != "srv-1":
                return httpx.Response(
                    400, headers={"DPoP-Nonce": "srv-1"}, json={"error": "use_dpop_nonce"}
                )
            return httpx.Response(200, json=DPOP_TOKEN)

        respx.post(TOKEN_EP).mock(side_effect=handler)
        client = OAuthClient(base_url=BASE)
        token = client.client_credentials("c", "s", "openid", dpop_private_key=key)
        assert token["token_type"] == "DPoP"
        assert seen == [None, "srv-1"]
        assert client.get_dpop_nonce(TOKEN_EP) == "srv-1"

        # Next call reuses the cached nonce without a round-trip.
        client.client_credentials("c", "s", "openid", dpop_private_key=key)
        assert seen[-1] == "srv-1" and len(seen) == 3

    @respx.mock
    def test_persistent_challenge_raises_with_nonce(self, key):
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: httpx.Response(
                400, headers={"DPoP-Nonce": str(uuid.uuid4())}, json={"error": "use_dpop_nonce"}
            )
        )
        with pytest.raises(VerifyError) as exc:
            OAuthClient(base_url=BASE).client_credentials("c", "s", "openid", dpop_private_key=key)
        assert exc.value.error == "use_dpop_nonce"
        assert exc.value.status_code == 400
        assert exc.value.dpop_nonce
        assert respx.calls.call_count == 2  # exactly one retry

    @respx.mock
    def test_no_retry_without_dpop_key(self):
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(
                400, headers={"DPoP-Nonce": "n"}, json={"error": "use_dpop_nonce"}
            )
        )
        with pytest.raises(VerifyError):
            OAuthClient(base_url=BASE).client_credentials("c", "s", "openid")
        assert respx.calls.call_count == 1

    @respx.mock
    def test_nonce_from_success_response_is_cached(self, key):
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(200, headers={"DPoP-Nonce": "next"}, json=DPOP_TOKEN)
        )
        client = OAuthClient(base_url=BASE)
        client.client_credentials("c", "s", "openid", dpop_private_key=key)
        assert client.get_dpop_nonce(TOKEN_EP) == "next"

    @respx.mock
    def test_other_errors_carry_status_code(self, key):
        respx.post(TOKEN_EP).mock(
            return_value=httpx.Response(400, json={"error": "invalid_dpop_proof"})
        )
        with pytest.raises(VerifyError) as exc:
            OAuthClient(base_url=BASE).client_credentials("c", "s", "openid", dpop_private_key=key)
        assert exc.value.error == "invalid_dpop_proof"
        assert exc.value.status_code == 400
        assert respx.calls.call_count == 1

    @respx.mock
    def test_device_poll_retries_nonce(self, key):
        def handler(request: httpx.Request) -> httpx.Response:
            if _payload(request.headers["dpop"]).get("nonce") != "dn":
                return httpx.Response(
                    400, headers={"DPoP-Nonce": "dn"}, json={"error": "use_dpop_nonce"}
                )
            return httpx.Response(200, json=DPOP_TOKEN)

        respx.post(TOKEN_EP).mock(side_effect=handler)
        token = OAuthClient(base_url=BASE).poll_device_token(
            "c", "dc", interval=0, expires_in=10, dpop_private_key=key
        )
        assert token["token_type"] == "DPoP"
        assert respx.calls.call_count == 2

    @respx.mock
    def test_device_poll_non_json_raises_verify_error(self):
        respx.post(TOKEN_EP).mock(return_value=httpx.Response(502, text="<html>bad gateway"))
        with pytest.raises(VerifyError) as exc:
            OAuthClient(base_url=BASE).poll_device_token("c", "dc", interval=0, expires_in=5)
        assert exc.value.status_code == 502


# ══════════════════════════════════════════════════════════════════════════════
# DPoP on every token-endpoint grant
# ══════════════════════════════════════════════════════════════════════════════


class TestDPoPOnAllGrants:
    @pytest.mark.parametrize(
        "call",
        [
            lambda c, k: c.password_grant(
                "c", "s", "u", "p", "Basic x", scope="openid", dpop_private_key=k
            ),
            lambda c, k: c.token_exchange("c", "s", "subj", "act", dpop_private_key=k),
            lambda c, k: c.jwt_bearer_grant("assertion", client_id="c", dpop_private_key=k),
        ],
        ids=["password", "token_exchange", "jwt_bearer"],
    )
    @respx.mock
    def test_grant_sends_proof(self, key, call):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["proof"] = request.headers.get("dpop")
            return httpx.Response(200, json=DPOP_TOKEN)

        respx.post(TOKEN_EP).mock(side_effect=handler)
        call(OAuthClient(base_url=BASE), key)
        verify_dpop_proof(captured["proof"], "POST", TOKEN_EP, expected_jkt=compute_jkt(key))

    def test_authorization_url_dpop_jkt(self, key):
        url = build_authorization_url(
            f"{BASE}/oauth2/authorize", "c", "https://app/cb", "chal", dpop_jkt=compute_jkt(key)
        )
        assert "dpop_jkt=" + compute_jkt(key) in url


# ══════════════════════════════════════════════════════════════════════════════
# Resource requests
# ══════════════════════════════════════════════════════════════════════════════


class TestDPoPRequest:
    @respx.mock
    def test_resource_nonce_challenge_retried(self, key):
        def handler(request: httpx.Request) -> httpx.Response:
            p = _payload(request.headers["dpop"])
            assert request.headers["authorization"] == "DPoP at"
            assert p["ath"] == compute_ath("at")
            if p.get("nonce") != "rn":
                return httpx.Response(
                    401,
                    headers={
                        "DPoP-Nonce": "rn",
                        "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                    },
                )
            return httpx.Response(200, json={"ok": True})

        respx.get(RESOURCE).mock(side_effect=handler)
        r = OAuthClient(base_url=BASE).dpop_request("GET", RESOURCE, "at", key)
        assert r.status_code == 200
        assert respx.calls.call_count == 2

    @respx.mock
    def test_plain_401_not_retried(self, key):
        respx.get(RESOURCE).mock(
            return_value=httpx.Response(
                401, headers={"WWW-Authenticate": 'DPoP error="invalid_token"'}
            )
        )
        r = OAuthClient(base_url=BASE).dpop_request("GET", RESOURCE, "at", key)
        assert r.status_code == 401
        assert respx.calls.call_count == 1


# ══════════════════════════════════════════════════════════════════════════════
# Verifier hardening
# ══════════════════════════════════════════════════════════════════════════════


class TestVerifierHardening:
    @pytest.mark.parametrize(
        "proof_htu",
        [
            RESOURCE + "?q=1#frag",
            "https://API.EXAMPLE.COM/photos",
            "https://api.example.com:443/photos",
        ],
    )
    def test_htu_compared_after_normalisation(self, key, proof_htu):
        verify_dpop_proof(_hand_proof(key, htu=proof_htu), "GET", RESOURCE)

    def test_htu_different_path_still_rejected(self, key):
        with pytest.raises(ValueError, match="htu"):
            verify_dpop_proof(_hand_proof(key, htu=RESOURCE + "/x"), "GET", RESOURCE)

    def test_normalize_htu(self):
        assert _normalize_htu("HTTPS://Host:443") == "https://host/"
        assert _normalize_htu("http://h:8080/a?b") == "http://h:8080/a"
        assert _normalize_htu("http://h:80/a") == "http://h/a"

    def test_fractional_iat_accepted(self, key):
        verify_dpop_proof(_hand_proof(key, iat=time.time()), "GET", RESOURCE)

    def test_boolean_iat_rejected(self, key):
        with pytest.raises(ValueError, match="iat"):
            verify_dpop_proof(_hand_proof(key, iat=True), "GET", RESOURCE)

    def test_expected_nonce(self, key):
        proof = generate_dpop_proof(key, "GET", RESOURCE, nonce="n1")
        verify_dpop_proof(proof, "GET", RESOURCE, expected_nonce="n1")
        with pytest.raises(ValueError, match="nonce"):
            verify_dpop_proof(proof, "GET", RESOURCE, expected_nonce="n2")
        with pytest.raises(ValueError, match="nonce"):
            verify_dpop_proof(
                generate_dpop_proof(key, "GET", RESOURCE), "GET", RESOURCE, expected_nonce="n1"
            )

    def test_replay_cache_rejects_second_use(self, key):
        cache = InMemoryDPoPReplayCache()
        proof = generate_dpop_proof(key, "GET", RESOURCE)
        verify_dpop_proof(proof, "GET", RESOURCE, replay_cache=cache)
        with pytest.raises(ValueError, match="replay"):
            verify_dpop_proof(proof, "GET", RESOURCE, replay_cache=cache)

    def test_failed_proof_does_not_consume_jti(self, key):
        cache = InMemoryDPoPReplayCache()
        proof = generate_dpop_proof(key, "GET", RESOURCE)
        with pytest.raises(ValueError):
            verify_dpop_proof(proof, "POST", RESOURCE, replay_cache=cache)
        verify_dpop_proof(proof, "GET", RESOURCE, replay_cache=cache)

    def test_replay_cache_expiry(self):
        cache = InMemoryDPoPReplayCache(ttl=1)
        assert cache.check_and_store("j")
        assert not cache.check_and_store("j")
        cache._seen["j"] = time.time() - 1
        assert cache.check_and_store("j")

    @respx.mock
    def test_introspect_dpop_token_uses_replay_cache(self, key):
        jkt = compute_jkt(key)
        respx.post(INTROSPECT_EP).mock(
            return_value=httpx.Response(200, json={"active": True, "cnf": {"jkt": jkt}})
        )
        client = OAuthClient(base_url=BASE)
        cache = InMemoryDPoPReplayCache()
        proof = generate_dpop_proof(key, "GET", RESOURCE, access_token="at")
        client.introspect_dpop_token(
            "at", proof, "GET", RESOURCE, replay_cache=cache, client_id="rs", client_secret="x"
        )
        with pytest.raises(VerifyError) as exc:
            client.introspect_dpop_token(
                "at", proof, "GET", RESOURCE, replay_cache=cache, client_id="rs", client_secret="x"
            )
        assert exc.value.error == "invalid_dpop_proof"


# ══════════════════════════════════════════════════════════════════════════════
# private_key_jwt
# ══════════════════════════════════════════════════════════════════════════════


class TestPrivateKeyJWT:
    def test_assertion_claims_and_audience(self, key):
        a = generate_client_assertion_jwt("cid", TOKEN_EP, key, key_id="k1")
        claims = _payload(a)
        assert claims["iss"] == claims["sub"] == "cid"
        assert claims["aud"] == TOKEN_EP
        assert claims["exp"] - claims["iat"] == 300
        header = json.loads(base64.urlsafe_b64decode(a.split(".")[0] + "=="))
        assert header == {"alg": "RS256", "typ": "JWT", "kid": "k1"}

        aud = [f"{BASE}/oauth2", TOKEN_EP]
        assert (
            _payload(generate_client_assertion_jwt("cid", TOKEN_EP, key, audience=aud))["aud"]
            == aud
        )

    @respx.mock
    def test_client_credentials_private_key_jwt(self, key):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["form"] = _form(request)
            captured["auth"] = request.headers.get("authorization")
            captured["dpop"] = request.headers.get("dpop")
            return httpx.Response(200, json=DPOP_TOKEN)

        respx.post(TOKEN_EP).mock(side_effect=handler)
        assertion = generate_client_assertion_jwt("cid", TOKEN_EP, key)
        OAuthClient(base_url=BASE).client_credentials(
            "cid", scope="openid", client_assertion=assertion, dpop_private_key=key
        )
        form = captured["form"]
        assert form["client_assertion"] == assertion
        assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE_JWT
        assert form["client_id"] == "cid"
        assert "client_secret" not in form
        assert captured["auth"] is None
        assert captured["dpop"]

    @respx.mock
    def test_client_credentials_secret_post(self):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: (
                captured.update(form=_form(r), auth=r.headers.get("authorization")),
                httpx.Response(200, json=DPOP_TOKEN),
            )[1]
        )
        OAuthClient(base_url=BASE).client_credentials(
            "cid", "sec", "openid", client_secret_post=True
        )
        assert captured["form"]["client_secret"] == "sec"
        assert captured["auth"] is None

    @respx.mock
    @pytest.mark.parametrize("grant", ["client_credentials", "password"])
    def test_secret_wins_over_unrelated_authorization_header(self, grant):
        """Regression: IBM_AUTHZ_HEADER held a Bearer token; the SDK must still send
        client credentials (CSIAQ0147E 'client_id is missing' otherwise)."""
        captured: dict = {}
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: (
                captured.update(auth=r.headers.get("authorization")),
                httpx.Response(200, json=DPOP_TOKEN),
            )[1]
        )
        c = OAuthClient(base_url=BASE)
        if grant == "client_credentials":
            c.client_credentials("cid", "sec", "openid", "Bearer some-api-token")
        else:
            c.password_grant("cid", "sec", "u", "p", "Bearer some-api-token")
        assert captured["auth"] == "Basic " + base64.b64encode(b"cid:sec").decode()

    @respx.mock
    @pytest.mark.parametrize("grant", ["client_credentials", "password"])
    def test_header_only_is_sent_as_given_with_client_id(self, grant):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: (
                captured.update(auth=r.headers.get("authorization"), form=_form(r)),
                httpx.Response(200, json=DPOP_TOKEN),
            )[1]
        )
        c = OAuthClient(base_url=BASE)
        if grant == "client_credentials":
            c.client_credentials("cid", scope="openid", authorization_header="Basic PREBUILT")
        else:
            c.password_grant("cid", "", "u", "p", "Basic PREBUILT")
        assert captured["auth"] == "Basic PREBUILT"
        assert captured["form"]["client_id"] == "cid"

    def test_client_credentials_requires_credentials(self):
        with pytest.raises(ValueError):
            OAuthClient(base_url=BASE).client_credentials("cid", scope="openid")

    @respx.mock
    @pytest.mark.parametrize("explicit_type", [None, CLIENT_ASSERTION_TYPE_JWT])
    def test_introspection_sends_assertion(self, key, explicit_type):
        captured: dict = {}
        respx.post(INTROSPECT_EP).mock(
            side_effect=lambda r: (
                captured.update(form=_form(r)),
                httpx.Response(200, json={"active": True}),
            )[1]
        )
        assertion = generate_client_assertion_jwt("rs", TOKEN_EP, key)
        OAuthClient(base_url=BASE).introspect_token(
            "tok", client_id="rs", client_assertion=assertion, client_assertion_type=explicit_type
        )
        form = captured["form"]
        assert form["token"] == "tok"
        assert form["client_id"] == "rs"
        assert form["client_assertion"] == assertion
        assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE_JWT


# ══════════════════════════════════════════════════════════════════════════════
# private_key_jwt + DPoP nonce retry: fresh assertion per attempt
# ══════════════════════════════════════════════════════════════════════════════


class TestAssertionFactory:
    @respx.mock
    def test_nonce_retry_uses_fresh_assertion_when_callable(self, key):
        seen: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(_form(request)["client_assertion"])
            if _payload(request.headers["dpop"]).get("nonce") != "n1":
                return httpx.Response(
                    400, headers={"DPoP-Nonce": "n1"}, json={"error": "use_dpop_nonce"}
                )
            return httpx.Response(200, json=DPOP_TOKEN)

        respx.post(TOKEN_EP).mock(side_effect=handler)
        OAuthClient(base_url=BASE).client_credentials(
            "cid",
            scope="openid",
            client_assertion=lambda: generate_client_assertion_jwt("cid", TOKEN_EP, key),
            dpop_private_key=key,
        )
        assert len(seen) == 2
        assert seen[0] != seen[1]
        assert _payload(seen[0])["jti"] != _payload(seen[1])["jti"]

    @respx.mock
    def test_static_assertion_is_resent_unchanged(self, key):
        seen: list = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(_form(request)["client_assertion"])
            if len(seen) == 1:
                return httpx.Response(
                    400, headers={"DPoP-Nonce": "n1"}, json={"error": "use_dpop_nonce"}
                )
            return httpx.Response(200, json=DPOP_TOKEN)

        respx.post(TOKEN_EP).mock(side_effect=handler)
        assertion = generate_client_assertion_jwt("cid", TOKEN_EP, key)
        OAuthClient(base_url=BASE).client_credentials(
            "cid", scope="openid", client_assertion=assertion, dpop_private_key=key
        )
        assert seen == [assertion, assertion]

    @respx.mock
    def test_introspection_accepts_callable(self, key):
        captured: dict = {}
        respx.post(INTROSPECT_EP).mock(
            side_effect=lambda r: (
                captured.update(form=_form(r)),
                httpx.Response(200, json={"active": True}),
            )[1]
        )
        assertion = generate_client_assertion_jwt("rs", TOKEN_EP, key)
        OAuthClient(base_url=BASE).introspect_token(
            "tok", client_id="rs", client_assertion=lambda: assertion
        )
        assert captured["form"]["client_assertion"] == assertion


class TestEmptyAuthorizationHeader:
    @respx.mock
    @pytest.mark.parametrize("header", ["", None])
    def test_password_grant_falls_back_to_basic(self, header):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: (
                captured.update(auth=r.headers.get("authorization")),
                httpx.Response(200, json=DPOP_TOKEN),
            )[1]
        )
        OAuthClient(base_url=BASE).password_grant("cid", "sec", "u", "p", header)
        assert captured["auth"] == "Basic " + base64.b64encode(b"cid:sec").decode()

    @respx.mock
    def test_client_credentials_empty_header_falls_back_to_basic(self):
        captured: dict = {}
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: (
                captured.update(auth=r.headers.get("authorization")),
                httpx.Response(200, json=DPOP_TOKEN),
            )[1]
        )
        OAuthClient(base_url=BASE).client_credentials("cid", "sec", "openid", "")
        assert captured["auth"] == "Basic " + base64.b64encode(b"cid:sec").decode()


class TestRefreshClientSecretPost:
    @respx.mock
    @pytest.mark.parametrize("post", [False, True])
    def test_refresh_auth_method(self, post):
        """IBM Verify apps limited to client_secret_post reject Basic with CSIAQ0330E."""
        captured: dict = {}
        respx.post(TOKEN_EP).mock(
            side_effect=lambda r: (
                captured.update(auth=r.headers.get("authorization"), form=_form(r)),
                httpx.Response(200, json=DPOP_TOKEN),
            )[1]
        )
        OAuthClient(base_url=BASE).refresh_access_token(
            "cid", "rt", client_secret="sec", client_secret_post=post
        )
        if post:
            assert captured["auth"] is None
            assert captured["form"]["client_secret"] == "sec"
            assert captured["form"]["client_id"] == "cid"
        else:
            assert captured["auth"] == "Basic " + base64.b64encode(b"cid:sec").decode()
            assert "client_secret" not in captured["form"]
