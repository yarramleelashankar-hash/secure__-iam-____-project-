# Secure Identity and Access Management System (IAM)

A B.Tech CSE minor project aligned with the Identity and Access Management syllabus:
- Authentication and authorization
- User and role management
- Role-Based Access Control (RBAC)
- TOTP multi-factor authentication (MFA)
- User lifecycle / provisioning
- Audit logging and security reports

## Requirements
- Python 3.10+
- VS Code (recommended)
- Internet only for installing Python dependencies

## Run on Windows
1. Extract the ZIP.
2. Open the `secure_iam_minor_project` folder in VS Code.
3. Open Terminal and run:

```powershell
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
py app.py
```

4. Open http://127.0.0.1:5000

## Demo accounts
| Role | Username | Password |
|---|---|---|
| Administrator | admin | Admin@12345 |
| Manager | manager | Manager@123 |
| Employee | employee | Employee@123 |

Change demo passwords immediately after first login. These credentials are for a local classroom demonstration only.

## MFA setup
1. Sign in.
2. Open Security → Set up authenticator app.
3. Scan the QR code using Google Authenticator, Microsoft Authenticator, or another TOTP app.
4. Enter the current six-digit code and enable MFA.
5. On the next login, enter username, password and the authenticator code.

## Main navigation
- Dashboard: system summary and recent activity
- Users: search, create, edit, activate/deactivate users (permission controlled)
- Roles & Permissions: configure permissions for Manager and Employee roles
- Audit Logs: inspect security events
- Profile: update your name and email
- Security: change password and configure MFA

## Project structure
```text
secure_iam_minor_project/
├── app.py
├── requirements.txt
├── README.md
├── PROJECT_REPORT.md
├── instance/                 # SQLite database created automatically
├── templates/
└── static/
    ├── css/style.css
    └── js/main.js
```

## Security and limitations
- Passwords are stored as Werkzeug password hashes, never plain text.
- Forms use CSRF protection.
- Authorization is enforced on server routes, not only hidden menu items.
- TOTP MFA uses a shared secret and time-based six-digit codes.
- This is an educational local project, not a production IAM platform.
- Before deployment: set a strong random `SECRET_KEY`, disable debug mode, use HTTPS, configure secure cookies, add rate limiting, backups, email verification, password reset, stronger monitoring and a production database.
- The demo app does not implement an LDAP server, SAML federation, OAuth/OIDC provider, or enterprise PAM vault. These can be discussed as future enhancements.

## Troubleshooting
- If `pip` is not recognized, use `py -m pip install -r requirements.txt`.
- If port 5000 is busy, change `app.run(debug=True)` to `app.run(port=5001, debug=True)` and open port 5001.
- To reset the local demo database, stop the app and delete `instance/iam.db`. It will be recreated with demo accounts on next run.
