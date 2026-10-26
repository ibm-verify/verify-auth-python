# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — Unreleased

Initial release of the IBM Verify Python SDK.

### Added

#### OAuth 2.0 / OIDC (`ibm_verify.oauth2.auth`, `ibm_verify.oauth2.grant_types`)

| Grant / feature | Class / method |
|---|---|
| Resource owner password credentials | `OAuthClient.password_grant()` |
| Client credentials | `OAuthClient.client_credentials()` |
| Token exchange (RFC 8693) | `OAuthClient.token_exchange()` |
| Authorization code + PKCE (RFC 7636) | `OAuthClient.build_authorization_url()` + `OAuthClient.exchange_code_for_token()` |
| Device authorization (RFC 8628) | `OAuthClient.request_device_code()` + `OAuthClient.poll_device_token()` |
| JWT bearer assertion (RFC 7523) | `OAuthClient.jwt_bearer_grant()` + `OAuthClient.generate_jwt_bearer_assertion()` |
| Refresh token (RFC 6749 §6) | `OAuthClient.refresh_access_token()` |
| Token introspection (RFC 7662) | `OAuthClient.introspect_token()` |
| OIDC discovery + JWKS | `OAuthClient.load_discovery()` + `OAuthClient.get_jwks()` |
| Dynamic Client Registration (RFC 7591 / RFC 7592) | `OAuthClient.register_client()`, `read_client()`, `update_client()`, `delete_client()` |
| Rich Authorization Requests — `authorization_details` (RFC 9396) | Supported on all grant methods via the `authorization_details=` keyword argument |
| DPoP — Demonstrating Proof of Possession (RFC 9449) | `dpop_private_key=` on every token method (`client_credentials()`, `exchange_code_for_token()`, `refresh_access_token()`, `password_grant()`, `token_exchange()`, `jwt_bearer_grant()`, `poll_device_token()`, `device_authorization_flow()`); automatic `use_dpop_nonce` retry with per-server nonce cache; `dpop_jkt=` on `build_authorization_url()`; `OAuthClient.dpop_request()`, `generate_dpop_key_pair()`, `generate_dpop_proof()`, `build_dpop_headers()`, `compute_dpop_jkt()`, `introspect_dpop_token()`; `verify_dpop_proof()` with `expected_nonce` and `InMemoryDPoPReplayCache` |
| `private_key_jwt` client authentication (RFC 7523 §2.2) | `client_assertion=` (a JWT, or a callable returning a fresh one per attempt) on `client_credentials()`, `exchange_code_for_token()`, `refresh_access_token()`, `jwt_bearer_grant()`, `introspect_token()`; `OAuthClient.generate_client_assertion_jwt()` (with `audience=`) |

All grant methods also accept `extra_params=` to merge arbitrary key/value pairs into
the token or authorization request body.

#### Client authentication, errors and transport

- Client authentication on token methods: `client_secret_basic` (default),
  `client_secret_post` (`client_secret_post=True` on `client_credentials()` and
  `refresh_access_token()`), `private_key_jwt` (`client_assertion=`), or a pre-encoded
  `authorization_header` when no secret is given.
- `VerifyError` exposes `status_code`, `error`, `error_description` and `dpop_nonce`.
- mTLS (`client_cert` / `client_key`) applies to every token and introspection request.
- `verify_dpop_proof()` compares `htu` after normalisation (query/fragment removed,
  scheme/host lower-cased, default port dropped) and accepts any numeric `iat`.

#### Tooling and packaging

- Python 3.9–3.12 supported
- Apache 2.0 license
- GitHub Actions CI: lint (ruff), test (pytest, 4-version matrix), build + import smoke-test
- GitHub Actions publish: OIDC trusted publishing to PyPI on version tags

---

[0.1.0]: https://github.com/ibm-verify/verify-auth-python/releases/tag/v0.1.0
