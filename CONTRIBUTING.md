# Contributing to Scorpio Pro

Thank you for your interest in contributing! We welcome all contributions — bug reports, feature requests, documentation improvements, and code.

## Code of Conduct

Be respectful and constructive. This project is for **authorised security testing only**.

## Getting Started

```bash
# 1. Fork the repository and clone your fork
git clone https://github.com/<your-username>/scorpio-pro.git
cd scorpio-pro

# 2. Create a virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install in editable mode with dev dependencies
pip install -e ".[dev]"

# 4. Run tests
pytest
```

## Development Workflow

1. **Create a branch** for your change: `git checkout -b feat/my-feature`
2. **Write tests** for all new functionality in `tests/`
3. **Ensure tests pass**: `pytest`
4. **Lint your code**: `ruff check scorpio_pro/`
5. **Type-check**: `mypy scorpio_pro/`
6. **Commit** with a descriptive message
7. **Open a Pull Request**

## Adding a New Scanner

1. Create `scorpio_pro/scanners/my_scanner.py`
2. Inherit from `BaseScanner` and implement `run()` and `check_prerequisites()`
3. Add the module name to `_SCANNER_MODULES` in `scorpio_pro/core/plugin_manager.py`
4. Add tests in `tests/test_my_scanner.py`

## Adding a Compliance Framework

1. Create `scorpio_pro/compliance/my_framework.py`
2. Inherit from `BaseComplianceFramework` and populate `controls`
3. Import and instantiate in `ComplianceEngine.evaluate()`

## Security

- **Never** add code that scans outside the authorised scope
- **Never** store credentials in plaintext or commit secrets
- All vulnerability checks must be non-destructive unless explicitly documented

## Reporting Vulnerabilities

Please report security vulnerabilities in this tool **privately** via GitHub Security Advisories, not in public issues.

## Style Guide

- Python 3.11+ type hints everywhere
- Docstrings on all public classes and methods (Google style)
- Line length ≤ 100 characters
- Use `ruff` for linting

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
