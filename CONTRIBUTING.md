# Contributing

Thank you for contributing to the IBM Verify Python SDK.

---

## Development setup

```bash
git clone https://github.com/ibm-verify/verify-auth-python.git
cd verify-auth-python

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## Running checks locally

These are the same checks that run in CI. All must pass before a PR is merged.

```bash
# Lint
ruff check oauth2/
ruff format --check oauth2/

# Tests
pytest

# Build
python -m build
pip install dist/*.whl
python -c "from oauth2.auth.client import OAuthClient; print('OK')"
```

---

## Pull request guidelines

- **One concern per PR.** Keep scope small so reviews are fast.
- **Match the existing code style.** `ruff format` enforces it.
- **Add or update tests** for any change to `auth/` or `grant_types/`.
- **Update `CHANGELOG.md`** — add an entry under `[Unreleased]` describing what changed.
- **Do not commit credentials.** `.env`, `certs/`, `*.pem`, `*.key` are all gitignored.
  See the security note in `README.md` before running the sample scripts.

---

## Commit message format

Use the conventional commits style:

```
<type>: <short summary>

[optional body]
```

Common types: `feat`, `fix`, `docs`, `ci`, `refactor`, `test`, `chore`.

Examples:
```
feat: add token revocation (RFC 7009)
fix: device code polling — show elapsed time counter
docs: document known limitations in CHANGELOG
ci: add ruff format check to lint job
```

---

## Reporting issues

Open a GitHub issue and include:

1. Python version (`python --version`)
2. SDK version (`pip show verify-auth-python`)
3. The grant type or API being called
4. The full error message and traceback (redact any credentials)
