Note: This is in reverse chronological order, so newer entries are added to the top.

# v0.1.0
18 November 2026

### IBM Verify Auth SDK for Python
* Initial release of the OAuth 2.0 / OIDC client for IBM Verify SaaS. `OAuthClient` (`from ibm_verify.oauth2 import OAuthClient`) is the single entry point.
* Grants: client credentials, resource owner password, authorization code + PKCE (RFC 7636), device authorization (RFC 8628), refresh token (RFC 6749 §6), token exchange (RFC 8693), and JWT bearer assertion (RFC 7523).
* OIDC discovery and JWKS (`load_discovery()`, `get_jwks()`), token introspection (RFC 7662), and Dynamic Client Registration with register, read, update and delete (RFC 7591 / RFC 7592).
* DPoP (RFC 9449) on every token method via `dpop_private_key=`, with automatic `use_dpop_nonce` retry and a per-server nonce cache. Includes `dpop_request()`, `dpop_jkt=` on `build_authorization_url()`, and resource-server helpers `verify_dpop_proof()` and `InMemoryDPoPReplayCache`.
* Client authentication: `client_secret_basic` (default), `client_secret_post`, `private_key_jwt` (RFC 7523 §2.2, `client_assertion=` accepts a JWT or a callable), or a pre-encoded `authorization_header`.
* Rich Authorization Requests (RFC 9396) on all grants via `authorization_details=`, and `extra_params=` for custom request parameters.
* mTLS (`client_cert` / `client_key`) on every token and introspection request.
* `VerifyError` exposes `status_code`, `error`, `error_description` and `dpop_nonce`.
* Supports Python 3.10, 3.11, 3.12, 3.13 and 3.14.
<br/>
<br/>