# Tests — IBM Verify Python SDK

This directory contains the unit tests for the OAuth 2.0 / OIDC layer of the SDK.

---

## Files

| File | Type | Needs live tenant? |
|---|---|---|
| `test_oauth_unit.py` | Unit tests — all flows mocked with [respx](https://lundberg.github.io/respx/) | ❌ No |
| `test_sdk.py` | Manual smoke test — calls live IBM Verify APIs | ✅ Yes |

---

## Quick start

All commands must be run from the **`verify-auth-python/`** directory (one level up from here),
not from inside `test/`.

```bash
# make sure you are in the right place
cd /path/to/verify-auth-python
```

### Run all unit tests

```bash
.venv/bin/pytest test/test_oauth_unit.py -v --no-cov
```

### Run the full test suite

```bash
.venv/bin/pytest --no-cov
```

### Run with coverage report

```bash
.venv/bin/pytest
# open htmlcov/index.html to see line-by-line coverage
```

---

## Running a subset

### One test class

```bash
.venv/bin/pytest test/test_oauth_unit.py::TestPasswordGrantMixin -v --no-cov
```

### One specific test

```bash
.venv/bin/pytest test/test_oauth_unit.py -v --no-cov -k "test_happy_path"
```

### All error-path tests

```bash
.venv/bin/pytest test/test_oauth_unit.py -v --no-cov -k "error"
```

---

## What `test_oauth_unit.py` covers

58 mocked unit tests across 12 test classes. No live tenant or `.env` file needed.

| Test class | SDK component | What is tested |
|---|---|---|
| `TestOAuthBaseEndpointResolution` | `OAuthBase` | Endpoint resolution priority: caller arg > constructor override > discovery > default path. Trailing-slash stripping. |
| `TestUtils` | `grant_types.utils` | PKCE pair length, uniqueness, S256 hash correctness. `build_authorization_url` params, auto-state, RAR serialisation, extra_params. |
| `TestDiscoveryMixin` | `DiscoveryMixin` | Discovery happy path, HTTP 404, network error. JWKS happy, JWKS 500. Cached metadata not re-fetched. |
| `TestPasswordGrantMixin` | `PasswordGrantMixin` | Happy path, `invalid_grant` → `VerifyError`, RAR body forwarded. |
| `TestClientCredentialsMixin` | `ClientCredentialsMixin` | Happy path, `invalid_client` → `VerifyError`, RAR forwarded, `extra_params` forwarded. |
| `TestTokenExchangeMixin` | `TokenExchangeMixin` | Happy path, grant type URN in body, error → `VerifyError`. |
| `TestAuthorizationCodeMixin` | `AuthorizationCodeMixin` | URL built with/without discovery. Public client exchange. Confidential client exchange. Stale code → `VerifyError`. |
| `TestDeviceCodeMixin` | `DeviceCodeMixin` | Request device code happy + 401 error. Poll: immediate approval, pending→approved, `access_denied`, `expired_token`, deadline exceeded, `slow_down` increases interval. |
| `TestJWTBearerMixin` | `JWTBearerMixin` | Happy path, grant type URN in body, error → `VerifyError`, explicit endpoint override. |
| `TestRefreshTokenMixin` | `RefreshTokenMixin` | Happy path with token rotation, grant type + token in body, `invalid_grant` → `VerifyError`, public client sends `client_id` in body. |
| `TestIntrospectMixin` | `IntrospectMixin` | Active token, inactive token, 401 → `VerifyError` (not a JSON crash), explicit endpoint override. |
| `TestVerifyError` | `VerifyError` | `__str__` with all fields, `__repr__`, minimal message-only error. |

---

## Common mistakes

### Running with `python` directly

```bash
# WRONG — test files have no __main__ block and pytest is not on system PATH
python test_oauth_unit.py
python test/test_oauth_unit.py
```

### Always use `.venv/bin/pytest` from `verify-auth-python/`

```bash
# CORRECT
cd verify-auth-python
.venv/bin/pytest test/test_oauth_unit.py -v --no-cov
```

### Running from inside the test directory

```bash
# WRONG — pytest won't find pyproject.toml and will mis-configure
cd test
pytest test_oauth_unit.py
```

---

## Running the manual smoke test (`test_sdk.py`)

`test_sdk.py` is not a pytest test — it is a standalone script that calls live IBM Verify
APIs. It requires real credentials in environment variables.

```bash
# set credentials first
export VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
export VERIFY_API_TOKEN=your-bearer-token

# run directly with python
.venv/bin/python test/test_sdk.py
```

> `test_sdk.py` is excluded from the pytest run by design. It is an integration
> smoke test, not a unit test, and will fail without live credentials.

---

## Installing test dependencies

If `pytest` or `respx` is missing, install the dev extras:

```bash
# from verify-auth-python/
pip install -e ".[dev]"
# or
uv pip install -e ".[dev]"
```

Dev extras include: `pytest`, `pytest-cov`, `pytest-asyncio`, `respx`.
