# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Verify OAuth — DPoP support (RFC 9449).

DPoP is not a separate grant: pass ``dpop_private_key`` to
``client_credentials()``, ``exchange_code_for_token()`` or ``refresh_access_token()``
to obtain a DPoP-bound token.  This mixin exposes the key/proof helpers and the
introspection check used with such tokens.
"""

from typing import Any, Optional

import httpx

from ibm_verify.oauth2.core.errors.errors import VerifyError
from ibm_verify.oauth2.grant_types.constants import DPOP_PROOF_LEEWAY, DPOP_PROOF_MAX_AGE
from ibm_verify.oauth2.grant_types.dpop import (
    build_dpop_headers,
    compute_jkt,
    generate_dpop_key_pair,
    generate_dpop_proof,
    is_use_dpop_nonce_challenge,
    verify_dpop_proof,
)


class DPoPMixin:
    """Mixin that adds DPoP helpers and DPoP-aware introspection.

    Requires :class:`~ibm_verify.oauth2.grant_types.base.OAuthBase` and
    :class:`~ibm_verify.oauth2.grant_types.flows.introspection.IntrospectMixin`
    in the MRO.
    """

    @staticmethod
    def generate_dpop_key_pair(key_type: str = "RSA", size_or_curve: Any = None) -> str:
        """Generate a DPoP key pair; returns the private key as PEM. See
        :func:`~ibm_verify.oauth2.grant_types.dpop.generate_dpop_key_pair`."""
        return generate_dpop_key_pair(key_type, size_or_curve)

    @staticmethod
    def compute_dpop_jkt(private_key: str) -> str:
        """Return the RFC 7638 thumbprint (``cnf.jkt``) of a DPoP key."""
        return compute_jkt(private_key)

    @staticmethod
    def generate_dpop_proof(
        private_key: str,
        http_method: str,
        http_url: str,
        access_token: Optional[str] = None,
        nonce: Optional[str] = None,
        algorithm: Optional[str] = None,
    ) -> str:
        """Create a DPoP proof JWT for one request. See
        :func:`~ibm_verify.oauth2.grant_types.dpop.generate_dpop_proof`."""
        return generate_dpop_proof(
            private_key, http_method, http_url, access_token, nonce, algorithm
        )

    @staticmethod
    def build_dpop_headers(
        access_token: str,
        private_key: str,
        http_method: str,
        http_url: str,
        nonce: Optional[str] = None,
        algorithm: Optional[str] = None,
    ) -> dict[str, str]:
        """Return ``Authorization: DPoP <token>`` and a fresh ``DPoP`` proof header
        for a call to a protected resource."""
        return build_dpop_headers(
            access_token, private_key, http_method, http_url, nonce, algorithm
        )

    def dpop_request(
        self,
        method: str,
        url: str,
        access_token: str,
        private_key: str,
        algorithm: Optional[str] = None,
        nonce: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        **request_kwargs: Any,
    ) -> httpx.Response:
        """Call a DPoP-protected resource with ``Authorization: DPoP`` and a fresh proof.

        If the resource server answers with a ``use_dpop_nonce`` challenge
        (``401`` + ``WWW-Authenticate: DPoP error="use_dpop_nonce"`` + ``DPoP-Nonce``),
        the request is retried once with the supplied nonce.  The latest nonce per
        origin is cached and reused on later calls.

        Args:
            method: HTTP method.
            url: Resource URL (``htu`` is derived from it).
            access_token: DPoP-bound access token.
            private_key: The PEM key the token is bound to.
            algorithm: Proof JWS algorithm (default inferred from the key).
            nonce: Explicit nonce; defaults to the cached one for this origin.
            headers: Extra request headers.
            **request_kwargs: Passed to ``httpx.Client.request`` (``json=``, ``params=``…).

        Returns:
            The final ``httpx.Response`` (not raised for status).
        """
        nonce = nonce or self.get_dpop_nonce(url)  # type: ignore[attr-defined]
        response: httpx.Response
        for attempt in range(2):
            request_headers = dict(headers or {})
            request_headers.update(
                build_dpop_headers(access_token, private_key, method, url, nonce, algorithm)
            )
            try:
                response = self._http_client.request(  # type: ignore[attr-defined]
                    method, url, headers=request_headers, **request_kwargs
                )
            except httpx.RequestError as exc:
                raise VerifyError(message=str(exc)) from exc
            server_nonce = self._remember_dpop_nonce(  # type: ignore[attr-defined]
                url, response.headers
            )
            if attempt == 0 and server_nonce and server_nonce != nonce:
                body: Any = None
                if response.status_code == 400:
                    try:
                        body = response.json()
                    except ValueError:
                        body = None
                if is_use_dpop_nonce_challenge(response.status_code, response.headers, body):
                    nonce = server_nonce
                    continue
            break
        return response

    def introspect_dpop_token(
        self,
        token: str,
        dpop_proof: str,
        http_method: str,
        http_url: str,
        expected_nonce: Optional[str] = None,
        replay_cache: Optional[Any] = None,
        max_age: int = DPOP_PROOF_MAX_AGE,
        leeway: int = DPOP_PROOF_LEEWAY,
        **introspect_kwargs: Any,
    ) -> dict[str, Any]:
        """Introspect a DPoP-bound token and validate the presented proof against it.

        Verifies that: the proof signature is valid; ``ath`` matches ``token``;
        ``htm``/``htu`` match the actual request; and the proof key's thumbprint
        equals ``cnf.jkt`` from the introspection response.

        Args:
            token: Access token presented by the caller.
            dpop_proof: Value of the ``DPoP`` header on the caller's request.
            http_method: Method of the caller's request.
            http_url: URL of the caller's request.
            expected_nonce: Nonce your resource server issued, if it uses nonces.
            replay_cache: ``jti`` replay cache, e.g.
                :class:`~ibm_verify.oauth2.grant_types.dpop.InMemoryDPoPReplayCache`.
                Strongly recommended — without one, a captured proof can be replayed
                for the same method and URL until it expires.
            max_age: Maximum proof age in seconds.
            leeway: Allowed clock skew in seconds.
            **introspect_kwargs: Passed to
                :meth:`~ibm_verify.oauth2.grant_types.flows.introspection.IntrospectMixin.introspect_token`
                (``client_id``, ``client_secret``, ``authorization_header``, …).

        Returns:
            The introspection response (unchanged). An inactive token is returned
            as-is without proof validation.

        Raises:
            VerifyError: ``error="invalid_dpop_proof"`` if the token is active but not
                DPoP-bound, or any proof check fails.
        """
        result: dict[str, Any] = self.introspect_token(  # type: ignore[attr-defined]
            token=token, **introspect_kwargs
        )
        if not result.get("active"):
            return result

        cnf = result.get("cnf")
        jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
        if not jkt:
            raise VerifyError(
                message="Token is not DPoP-bound (introspection has no cnf.jkt)",
                error="invalid_dpop_proof",
            )
        try:
            verify_dpop_proof(
                proof=dpop_proof,
                http_method=http_method,
                http_url=http_url,
                access_token=token,
                expected_jkt=jkt,
                max_age=max_age,
                leeway=leeway,
                expected_nonce=expected_nonce,
                replay_cache=replay_cache,
            )
        except ValueError as exc:
            raise VerifyError(
                message=str(exc),
                error="invalid_dpop_proof",
                error_description=str(exc),
            ) from exc
        return result
