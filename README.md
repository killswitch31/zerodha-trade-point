# Zerodha-Trade-Point

> Disclaimer:
> This project is intended only for managing your own Zerodha account and accounts of your close family members. Do not use this application to manage Zerodha accounts belonging to unrelated individuals or third parties.
> This project does not support algorithmic trading or automated order execution.

Django application to manage multiple Zerodha Kite accounts, role-based app users, and a browser-based trade dashboard.

This application is built using Python v3.14.

## Project Structure

```text
Zerodha-Trade-Point/
├── README.md
├── TESTING.md
├── LICENSE
├── requirements-dev.txt
├── .coveragerc
├── .github/
│   └── workflows/
│       └── tests.yml
└── zerodha_trade_point/
	├── manage.py
	├── requirements.txt
	├── startup.sh
	├── db.sqlite3
	├── app/
	│   ├── models.py
	│   ├── views.py
	│   ├── forms.py
	│   ├── tests.py
	│   ├── middleware.py
	│   ├── context_processors.py
	│   ├── migrations/
	│   ├── templates/
	│   │   └── app/
	│   └── static/
	│       └── app/
	├── staticfiles/
	└── zerodha_trade_point/
		├── settings.py
		├── urls.py
		└── wsgi.py
```

## **Clone And Run Locally**

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

#### 2.1 Verify you are inside venv

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

After first login, create another app user with role `admin_only` from `/managezkusers/`.
Use that admin account for day-to-day operations and avoid using the Django superuser account every time.

#### 5.1 Change superuser password

Use either of the following methods:

Method A (interactive command):

```bash
python manage.py changepassword <SUPERUSER_USERNAME>
```

Method B (from Django admin):

1. Login to `/admin/` with superuser credentials.
2. Open `Users`.
3. Select the superuser account.
4. Click the password change link and save.

### 6. Local vs production configuration

Security-sensitive settings are driven automatically by the `DJANGO_DEBUG`
environment variable, so you no longer need to hand-edit `settings.py` when
switching between local development and production.

- `DJANGO_DEBUG` unset (or anything other than `False`) &rarr; **debug mode** (local defaults).
- `DJANGO_DEBUG=False` &rarr; **production mode** (secure defaults).

What each mode applies in `zerodha_trade_point/settings.py`:

| Setting | Local (`DEBUG=True`) | Production (`DEBUG=False`) |
| --- | --- | --- |
| `DEBUG` | `True` | `False` |
| `SECRET_KEY` fallback | random `uuid.uuid4()` | `None` (must set `DJANGO_SECRET_KEY`) |
| `SECURE_SSL_REDIRECT` | `False` | `True` |
| `SESSION_COOKIE_SECURE` | `False` | `True` |
| `CSRF_COOKIE_SECURE` | `False` | `True` |
| Session backend | in-memory (cleared on restart) | database-backed |

For **local HTTP development** with `runserver`, no changes are required — the
default (`DJANGO_DEBUG` unset) already runs in debug mode with an auto-generated
secret key and insecure cookies suitable for `http://127.0.0.1:8000/`.

To force debug mode explicitly:

macOS/Linux:

```bash
export DJANGO_DEBUG=True
```

Windows (PowerShell):

```powershell
$env:DJANGO_DEBUG = "True"
```

For **production**, set `DJANGO_DEBUG=False` (see the Azure app settings step
below) and provide a strong `DJANGO_SECRET_KEY`, since there is no insecure
fallback when debug is off.

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

### 8. Run tests and coverage

Detailed testing and coverage documentation lives in [TESTING.md](TESTING.md).

Quick commands:

```bash
pip install -r ../requirements-dev.txt
python manage.py test app.tests
coverage run manage.py test app.tests
coverage report
coverage run --rcfile ../.coveragerc manage.py test app.tests
coverage report --rcfile ../.coveragerc
```

## **Deploy To Azure App Service**

You can deploy this project to an Azure Web App named `<YOUR_WEBAPP_NAME>` even though the Django project package is named `zerodha_trade_point`.

Important distinction:

- Azure Web App name: `<YOUR_WEBAPP_NAME>`
- Django WSGI module: `zerodha_trade_point.wsgi:application`

Use your own values for subscription, resource group, plan, and app name.

Example placeholders used below:

- `<YOUR_SUBSCRIPTION_ID>`
- `<YOUR_RESOURCE_GROUP>`
- `<YOUR_APP_SERVICE_PLAN>`
- `<YOUR_WEBAPP_NAME>`

### 1. Login and select subscription

```bash
az login
az account set --subscription <YOUR_SUBSCRIPTION_ID>
```

### 2. Create resource group (if needed)

```bash
az group create --name <YOUR_RESOURCE_GROUP> --location <YOUR_AZURE_REGION>
```

### 3. Create Linux App Service plan

Note: `B1` is a paid App Service plan and will incur Azure charges. Before creating the plan, review Azure pricing and explore cheaper or free plan options in official Azure documentation.

```bash
az appservice plan create \
	--name <YOUR_APP_SERVICE_PLAN> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--is-linux \
	--sku B1
```

### 4. Create web app with Python runtime

```bash
az webapp create \
	--name <YOUR_WEBAPP_NAME> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--plan <YOUR_APP_SERVICE_PLAN> \
	--runtime "PYTHON:3.14"
```

### 5. Configure app settings

Set Django host and secret-related settings using app settings:

```bash
az webapp config appsettings set \
	--name <YOUR_WEBAPP_NAME> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--settings \
		DJANGO_DEBUG="False" \
		DJANGO_ALLOWED_HOSTS="<YOUR_WEBAPP_NAME>.azurewebsites.net" \
		DJANGO_CSRF_TRUSTED_ORIGINS="https://<YOUR_WEBAPP_NAME>.azurewebsites.net" \
		DJANGO_SECRET_KEY="<YOUR_STRONG_SECRET_KEY>" \
		LOGIN_RATE_LIMIT_ATTEMPTS="5" \
		LOGIN_RATE_LIMIT_WINDOW_SECONDS="900" \
		SCM_DO_BUILD_DURING_DEPLOYMENT="true"
```

`SCM_DO_BUILD_DURING_DEPLOYMENT=true` ensures App Service runs build steps during deployment in production.

`DJANGO_DEBUG=False` puts the app in production mode (secure cookies, SSL redirect, database-backed sessions, and no insecure secret-key fallback).

The login page supports Cloudflare Turnstile. To enable strong CAPTCHA on `/login`, also set:

```bash
az webapp config appsettings set \
	--name <YOUR_WEBAPP_NAME> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--settings \
		TURNSTILE_SITE_KEY="<YOUR_TURNSTILE_SITE_KEY>" \
		TURNSTILE_SECRET_KEY="<YOUR_TURNSTILE_SECRET_KEY>"
```

If `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are not set, login continues to work without the CAPTCHA widget.

If needed, also set Zerodha config values:

```bash
az webapp config appsettings set \
	--name <YOUR_WEBAPP_NAME> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--settings \
		KITE_API_KEY="<YOUR_KITE_API_KEY>" \
		KITE_API_SECRET="<YOUR_KITE_API_SECRET>"
```

### 6. Configure startup command

This project WSGI module is `zerodha_trade_point.wsgi:application`.

```bash
az webapp config set \
	--name <YOUR_WEBAPP_NAME> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--startup-file "gunicorn zerodha_trade_point.wsgi:application --bind=0.0.0.0:8000 --workers=2 --timeout=120"
```

If your Azure Web App name is `<YOUR_WEBAPP_NAME>`, the startup command is still:

```bash
gunicorn zerodha_trade_point.wsgi:application --bind=0.0.0.0:8000 --workers=2 --timeout=120
```

Do not change it to `gunicorn <YOUR_WEBAPP_NAME>.wsgi`; `<YOUR_WEBAPP_NAME>` is the Azure site name, not a Python module.

### 7. Deploy code

From repo root:

```bash
az webapp up \
	--name <YOUR_WEBAPP_NAME> \
	--resource-group <YOUR_RESOURCE_GROUP> \
	--runtime "PYTHON:3.14" \
	--sku B1
```

### 8. Open app

```bash
az webapp browse --name <YOUR_WEBAPP_NAME> --resource-group <YOUR_RESOURCE_GROUP>
```

### Notes for your original commands

- Use your own placeholders, not fixed values.
- `az webapp config appsettings set` is the standard command for environment variables.
- Startup module should be `zerodha_trade_point.wsgi:application`.
- `<YOUR_WEBAPP_NAME>` can be the Azure Web App name, but it must not be used as the Gunicorn Python module path.
- Keep app name consistent in all commands (`<YOUR_WEBAPP_NAME>`).

## Authentication And Core Data Model

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

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

- Endpoint: `/managezkusers/` (admin only)
- Admins can create app login users and assign roles (`self_only`, `admin_only`, `trader_all`).
- Users cannot self-register in this application.
- After creating a user, admins must share username and password with that user through a secure channel.
- Admins can also change/reset a user's password from this endpoint.

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

This application only supports placing, modifying, and cancelling orders with the following values:

- Product: `CNC` / `MIS`
- Validity: `DAY`
- Order Type: `MARKET` / `LIMIT`
- Variety: `REGULAR`

- Choose side: `BUY` or `SELL`.
- Choose exchange: `NSE` or `BSE`.
- Search security symbol/name (autocomplete).
- Enter quantity, product (`CNC`/`MIS`), order type (`MARKET`/`LIMIT`), and price when needed.

### TradingView chart widget panel

- A `Load TradingView Chart` button is available on `/trade/` above the place order section.
- Clicking the button opens an embedded TradingView advanced chart panel in the same page.
- The chart panel has close buttons at the top, left side, and bottom.
- Popup dimensions used by the TradingView popup button are:
	- Width: `1200`
	- Height: `1000`

Disclaimer:

- The embedded chart supports only BSE listed securities.
- NSE listed securities are not supported in the embedded panel.
- If an NSE listed symbol is searched from within TradingView, open that symbol in a new TradingView tab.

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
