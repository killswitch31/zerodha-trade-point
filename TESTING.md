# Testing Guide

This document covers how to run tests, generate coverage, understand the current test layout, and use the repo's testing-related files.

## Scope

The project currently uses Django's built-in test runner and keeps the test suite in:

- `zerodha_trade_point/app/tests.py`

The suite includes:

- form validation tests
- login CAPTCHA and rate-limit tests
- login page rendering tests
- model and admin behavior tests
- role and permission helper tests
- Zerodha auth configuration flow tests
- Kite callback tests
- trade page and trade action tests
- market data endpoint tests
- helper and fallback branch tests
- integration-style login and trade flow tests

## Prerequisites

From the repository root:

1. Create and activate the virtual environment.
2. Install application dependencies.
3. Install development dependencies for coverage.

macOS/Linux:

```bash
cd zerodha_trade_point
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r ../requirements-dev.txt
```

Windows PowerShell:

```powershell
cd zerodha_trade_point
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
pip install -r ..\requirements-dev.txt
```

## Run Tests

From `zerodha_trade_point/`:

Run the full application suite:

```bash
python manage.py test app.tests
```

Run a specific test class:

```bash
python manage.py test app.tests.LoginProtectionFormTests
```

Run multiple specific test classes:

```bash
python manage.py test \
  app.tests.LoginProtectionFormTests \
  app.tests.LoginPageRenderingTests
```

## Coverage

Coverage is configured with the root-level file:

- `.coveragerc`

Development-only coverage dependency is declared in:

- `requirements-dev.txt`

From `zerodha_trade_point/`, run:

```bash
coverage erase
coverage run --rcfile ../.coveragerc manage.py test app.tests
coverage report --rcfile ../.coveragerc
```

Generate an HTML report:

```bash
coverage html --rcfile ../.coveragerc
```

Then open:

- `zerodha_trade_point/htmlcov/index.html`

## Current Coverage Baseline

Latest measured baseline in this workspace:

- total coverage: `91.70%`
- `app/views.py`: `89.83%`
- `app/forms.py`: `97.73%`
- `app/models.py`: `100.00%`
- `app/admin.py`: `100.00%`
- `app/context_processors.py`: `100.00%`
- `app/middleware.py`: `100.00%`

This baseline will change as the code or tests change.

## CI

GitHub Actions runs tests and coverage automatically on pushes and pull requests via:

- `.github/workflows/tests.yml`

The workflow:

1. checks out the repository
2. installs Python `3.14`
3. installs dependencies from `requirements-dev.txt`
4. runs `coverage run ... manage.py test app.tests`
5. prints a terminal coverage report

## Files Related To Testing

- `TESTING.md`: dedicated testing documentation
- `requirements-dev.txt`: developer-only dependencies, including coverage
- `.coveragerc`: coverage configuration
- `.github/workflows/tests.yml`: CI workflow for tests and coverage
- `zerodha_trade_point/app/tests.py`: application test suite

## Notes

- Local coverage artifacts are ignored by git through `.gitignore`.
- The test suite uses Django's test database automatically.
- Some tests override `SECRET_KEY` or `SECURE_SSL_REDIRECT` locally to make page rendering and auth flows testable.
- Login protection tests cover both Cloudflare Turnstile behavior and server-side login throttling.

## Recommended Commands

Quick local verification:

```bash
cd zerodha_trade_point
./.venv/bin/python manage.py test app.tests
```

Full verification with coverage:

```bash
cd zerodha_trade_point
./.venv/bin/coverage erase
./.venv/bin/coverage run --rcfile ../.coveragerc manage.py test app.tests
./.venv/bin/coverage report --rcfile ../.coveragerc
```