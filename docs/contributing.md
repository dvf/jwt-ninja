---
icon: lucide/heart-handshake
---

# Contributing

Contributions are welcome. Submit a PR to [dvf/jwt-ninja](https://github.com/dvf/jwt-ninja).

## Development

```bash
# Clone and install
git clone https://github.com/dvf/jwt-ninja
cd jwt-ninja
uv sync

# Run tests
uv run pytest

# Lint + format
uv run ruff check .
uv run ruff format .

# Static type check
uv run pyrefly check
```

PRs are gated on all four checks. See [`check-and-test.yml`](https://github.com/dvf/jwt-ninja/blob/master/.github/workflows/check-and-test.yml).

## Documentation

The docs are built with [Zensical](https://zensical.org/) from the `docs/` directory:

```bash
# Live-reloading preview at http://localhost:8000
uv run zensical serve

# Production build into site/
uv run zensical build --clean
```

Docs deploy to GitHub Pages automatically on push to `master`.
