## Regenerating the SDK

```sh
# From verify-auth-python/
fern generate --group python-sdk --log-level debug --local
```

After generation, reinstall the editable package so the changes are picked up:

```sh
# With uv
uv pip install -e .

# With pip (if .venv is already active)
pip install -e .
```
