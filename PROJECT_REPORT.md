# MINOR PROJECT REPORT
## Secure Identity and Access Management System with RBAC and MFA

**Department:** Computer Science and Engineering  
**Project Type:** Minor Project  
**Technology Stack:** Python, Flask, SQLite, HTML, CSS, JavaScript

## 1. Abstract
The Secure Identity and Access Management System is a web-based application that manages digital identities and controls access to application resources. It provides authentication, authorization, role-based permissions, TOTP-based multi-factor authentication, account lifecycle management and audit logging. The project demonstrates how identity controls reduce unauthorized access and improve accountability in an organization.

## 2. Problem Statement
Organizations need a consistent way to create user accounts, assign access rights, disable accounts when no longer required and review security activity. Managing these tasks manually can lead to excessive permissions, weak accountability and unauthorized access. This project provides a centralized demonstration system for these IAM activities.

## 3. Objectives
1. Implement secure username/password authentication.
2. Store passwords using one-way password hashing.
3. Apply Role-Based Access Control (RBAC).
4. Add TOTP-based multi-factor authentication.
5. Support user creation, editing and deactivation.
6. Maintain audit records of important actions.
7. Present system information through an administrator dashboard.

## 4. Scope
The project is an educational prototype for a single organization. It includes local user accounts, three built-in roles, configurable role permissions, TOTP MFA and audit logs. LDAP directory integration, SAML, OAuth/OIDC federation and enterprise privileged access management are outside the current implementation and are future enhancements.

## 5. System Modules
- Authentication: validates the username and password and checks account status.
- MFA: validates a six-digit time-based one-time password from an authenticator app.
- User Management: creates, edits, searches and deactivates accounts.
- Role Management: maps permissions to roles.
- Authorization: checks permissions on the server for protected routes.
- Audit: stores timestamps, actor, action, details and source IP.
- Profile and Security: allows users to update profile details and change passwords.

## 6. System Requirements
**Hardware:** Dual-core processor or better, 4 GB RAM recommended, 500 MB free disk space.  
**Software:** Windows/Linux/macOS, Python 3.10+, Flask, SQLite, modern browser and VS Code.

## 7. Architecture
Browser UI → Flask routes → Authentication/authorization checks → SQLAlchemy models → SQLite database.  
TOTP verification is performed by the server using the user's enrolled secret and the current time window. Audit events are written to the database.

## 8. Database Design
- User: username, email, full name, password hash, role, active status, TOTP secret and MFA status.
- Role: role name and description.
- Permission: permission code and label.
- RolePermission: many-to-many mapping between roles and permissions.
- AuditLog: actor, action, details, IP address and timestamp.

## 9. Security Features
- Password hashing with Werkzeug.
- CSRF protection on form submissions.
- Session management through Flask-Login.
- Server-side permission checks.
- TOTP MFA support.
- Audit logging for sign-in and administrative events.
- Deactivation of accounts without deleting audit history.

## 10. Testing Plan
| Test | Expected result |
|---|---|
| Valid username/password | User signs in |
| Invalid password | Sign-in rejected |
| Inactive account | Sign-in rejected |
| Valid TOTP when MFA enabled | User signs in |
| Invalid TOTP | Sign-in rejected |
| Employee opens protected user page | Access denied |
| Administrator creates user | User record saved |
| Administrator changes role permissions | Permission mapping updated |
| User changes password with wrong current password | Change rejected |
| User logs out | Session ended and event recorded |

## 11. Future Enhancements
- LDAP/Active Directory connector.
- SAML single sign-on and OAuth 2.0 / OpenID Connect integration.
- Email-based OTP and account recovery.
- Password policy and login rate limiting.
- Approval workflows and access certification.
- Privileged Access Management (PAM) and secrets vault.
- Exportable audit reports and alerting.

## 12. Conclusion
The project demonstrates core IAM concepts through a practical web application. It combines authentication, authorization, RBAC, MFA, user lifecycle operations and auditing in one interface. It provides a foundation for understanding enterprise identity governance and access control.

## 13. References
1. Flask documentation: https://flask.palletsprojects.com/
2. Flask-Login documentation: https://flask-login.readthedocs.io/
3. Flask-SQLAlchemy documentation: https://flask-sqlalchemy.palletsprojects.com/
4. PyOTP documentation: https://pyauth.github.io/pyotp/
5. OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
6. OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
