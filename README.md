# Zerodha-Trade-Point

Django application to manage multiple Zerodha Kite accounts, role-based app users, and a browser-based trade dashboard.

This application is built using Python v3.14.

## Clone And Run Locally

### 1. Clone repository

```bash
git clone https://github.com/killswitch31/zerodha_trade_point.git
cd zerodha_trade_point/zerodha_trade_point
```

### 2. Create and activate virtual environment

macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2.1 Verify you are inside venv

After activation, your shell prompt usually shows `(.venv)`.

You can verify with:

```bash
which python
python --version
```

Expected Python path should point to `.venv`.

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Apply database migrations

```bash
python manage.py migrate
```

### 5. Create superuser

```bash
python manage.py createsuperuser
```

Follow prompts for username, email, and password.

### 6. Local settings note (important)

Current settings are production-leaning (`DEBUG = False`, SSL redirect enabled, secure cookies enabled).
For local HTTP development with `runserver`, update `zerodha_trade_point/settings.py` temporarily:

- Set `DEBUG = True`
- Set `SECURE_SSL_REDIRECT = False`
- Set `SESSION_COOKIE_SECURE = False`
- Set `CSRF_COOKIE_SECURE = False`

After deployment, revert these to secure values.

### 7. Start application

```bash
python manage.py runserver
```

If you want to be explicit about using venv Python:

macOS/Linux:

```bash
./.venv/bin/python manage.py runserver
```

Windows (PowerShell):

```powershell
.venv\Scripts\python manage.py runserver
```

Open:

- App: `http://127.0.0.1:8000/`
- Admin: `http://127.0.0.1:8000/admin/`

## Authentication And Core Data Model

### Entities and relationships

- Django `User`: app login account.
- `Profile` (one-to-one with `User`): stores role (`self_only`, `admin_only`, `trader_all`).
- `KiteUser` (many-to-one to `User` via `owner`): one Zerodha app credential set per API key.

In short:

- One app user has exactly one profile.
- One app user can own many Zerodha (`KiteUser`) accounts.

### Zerodha token lifecycle

- On auth callback, app stores `access_token` and `refresh_token`.
- When an API call gets token expiry (`TokenException`), app tries `renew_access_token(refresh_token, api_secret)` and retries once.
- If renewal fails, UI shows `Needs reauthentication`.

## User Roles And Permissions

### `admin_only` (and Django superuser)

- Can open `Manage Users` page.
- Can create/edit/delete app login users.
- Can configure Zerodha accounts for all users.
- Can view/trade all configured Zerodha accounts.

### `self_only`

- Can configure only their own Zerodha accounts.
- Can delete only their own configured Zerodha accounts.
- Can trade only their own Zerodha accounts.
- Cannot access `Manage Users`.

### `trader_all`

- Can trade all configured Zerodha accounts.
- Cannot configure/add/re-auth/delete Zerodha accounts.
- Cannot access user-management operations.

## How To Configure Zerodha (ZK) Users

Page: `/configurezkauth/`

1. Open `Configure ZK Auth` from Home.
2. Enter `API Key` and `API Secret`.
3. Click `Authenticate`.
4. Complete Zerodha OAuth and return to callback.
5. App stores user metadata and tokens.

On this page you can also:

- View all permitted stored accounts (scoped by role).
- See masked API key and secret with reveal buttons.
- Check token validity on-demand with `Check Access Token Validity`.
- Watch 10-minute token status recheck countdown.
- Re-authenticate an account when status needs re-authentication.

Redirect URL to configure in Zerodha app is shown on this page and can be copied directly.

## How Admin Manages App Users

Page: `/managezkusers/` (admin only)

### Create user

1. Enter username and password.
2. Choose role (`self_only`, `admin_only`, `trader_all`).
3. Submit `Create user`.

### Edit user

- Change password (optional) and role from Edit modal.

### Delete user

- Deletes app login user and all their associated Zerodha (`KiteUser`) records.
- Superuser accounts are protected from this delete flow.

## Trade Dashboard (`/trade/`) End-Panel Guide

1. Select Zerodha user from dropdown.
2. Confirm token badge (`Active` or `Needs reauthentication`).
3. Use `Check Access Token Validity` for immediate status probe.
4. Use `Refresh Trade Data` to fetch latest profile, orders, holdings, positions, and margin snapshot.

### Place order panel

- Choose side: `BUY` or `SELL`.
- Choose exchange: `NSE` or `BSE`.
- Search security symbol/name (autocomplete).
- Enter quantity, product (`CNC`/`MIS`), order type (`MARKET`/`LIMIT`), and price when needed.

### Open/Executed/Cancelled orders panels

- Open orders: `Modify` or `Cancel`.
- Executed/Cancelled: `Place again` for quick re-entry.

### Holdings and positions panels

- Displays row-level P&L and total P&L for holdings and positions.

## Key Routes

- `/` Home
- `/login/` Login
- `/configurezkauth/` Configure Zerodha auth
- `/managezkusers/` Admin user management
- `/deletezkuser/` Delete configured Zerodha account
- `/trade/` Trade dashboard
- `/kite/callback/` Zerodha OAuth callback
- `/token-statuses/` Live token status API

## Notes

- Default DB is SQLite (`db.sqlite3`).
- Keep secrets out of git.
- Review `.gitignore` before adding new infra/tooling files.
