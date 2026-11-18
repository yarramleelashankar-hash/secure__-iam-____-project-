import os
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Optional, EqualTo
from io import BytesIO
from sqlalchemy import or_

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "iam.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
os.makedirs(app.instance_path, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
csrf = CSRFProtect(app)

# ---------------------------- Database models ----------------------------
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    description = db.Column(db.String(200), default="")
    users = db.relationship("User", backref="role", lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(60), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)

class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey("permission.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("role_id", "permission_id"),)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    actor = db.Column(db.String(80), default="system")
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500), default="")
    ip_address = db.Column(db.String(60), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", foreign_keys=[user_id])

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def log_event(action, details="", user=None):
    actor = user.username if user else (current_user.username if current_user.is_authenticated else "anonymous")
    db.session.add(AuditLog(
        user_id=user.id if user else (current_user.id if current_user.is_authenticated else None),
        actor=actor, action=action, details=details[:500],
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr or "")[:60]
    ))
    db.session.commit()

def has_permission(code):
    if not current_user.is_authenticated or not current_user.is_active:
        return False
    if current_user.role and current_user.role.name == "Administrator":
        return True
    return db.session.query(RolePermission).join(Permission).filter(
        RolePermission.role_id == current_user.role_id, Permission.code == code
    ).first() is not None

def permission_required(code):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if not has_permission(code):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

@app.context_processor
def inject_globals():
    return {"has_permission": has_permission, "now": datetime.utcnow}

# ---------------------------- Forms ----------------------------
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    otp = StringField("Authenticator code (if enabled)", validators=[Optional(), Length(min=6, max=6)])

class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=40)])
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    role_id = SelectField("Role", coerce=int, validators=[DataRequired()])
    password = PasswordField("Temporary password", validators=[Optional(), Length(min=8, max=128)])
    is_active = BooleanField("Account active", default=True)

class ProfileForm(FlaskForm):
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])

class PasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField("Confirm new password", validators=[DataRequired(), EqualTo("new_password")])

# ---------------------------- Routes ----------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if not user or not user.check_password(form.password.data) or not user.is_active:
            log_event("LOGIN_FAILED", f"Failed login for username {form.username.data.strip()}")
            flash("Invalid credentials or inactive account.", "danger")
        elif user.mfa_enabled:
            if not form.otp.data or not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(form.otp.data, valid_window=1):
                log_event("MFA_FAILED", f"Invalid MFA code for {user.username}", user=user)
                flash("Authenticator code is missing or incorrect.", "danger")
            else:
                login_user(user)
                log_event("LOGIN_SUCCESS", "Login with MFA", user=user)
                return redirect(url_for("dashboard"))
        else:
            login_user(user)
            log_event("LOGIN_SUCCESS", "Password login (MFA not enabled)", user=user)
            return redirect(url_for("dashboard"))
    return render_template("login.html", form=form)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("LOGOUT", "User logged out")
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    stats = {
        "users": User.query.count(),
        "active": User.query.filter_by(is_active=True).count(),
        "roles": Role.query.count(),
        "events": AuditLog.query.count()
    }
    recent = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(7).all()
    return render_template("dashboard.html", stats=stats, recent=recent)

@app.route("/users")
@permission_required("users.view")
def users():
    q = request.args.get("q", "").strip()
    query = User.query.join(Role)
    if q:
        query = query.filter(or_(User.username.ilike(f"%{q}%"), User.full_name.ilike(f"%{q}%"), User.email.ilike(f"%{q}%")))
    all_users = query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=all_users, q=q)

@app.route("/users/new", methods=["GET", "POST"])
@permission_required("users.manage")
def user_new():
    form = UserForm()
    form.role_id.choices = [(r.id, r.name) for r in Role.query.order_by(Role.name).all()]
    if form.validate_on_submit():
        if User.query.filter(or_(User.username == form.username.data.strip(), User.email == form.email.data.strip().lower())).first():
            flash("Username or email already exists.", "danger")
        elif not form.password.data:
            flash("Set a temporary password of at least 8 characters.", "warning")
        else:
            u = User(username=form.username.data.strip(), full_name=form.full_name.data.strip(),
                     email=form.email.data.strip().lower(), role_id=form.role_id.data,
                     is_active=form.is_active.data)
            u.set_password(form.password.data)
            db.session.add(u); db.session.commit()
            log_event("USER_CREATED", f"Created account {u.username}")
            flash("User created successfully.", "success")
            return redirect(url_for("users"))
    return render_template("user_form.html", form=form, heading="Create user")

@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@permission_required("users.manage")
def user_edit(user_id):
    u = db.get_or_404(User, user_id)
    if u.id == current_user.id:
        flash("Use Profile to edit your own details.", "warning")
        return redirect(url_for("users"))
    form = UserForm(obj=u)
    form.role_id.choices = [(r.id, r.name) for r in Role.query.order_by(Role.name).all()]
    if request.method == "GET":
        form.role_id.data = u.role_id
        form.is_active.data = u.is_active
    if form.validate_on_submit():
        duplicate = User.query.filter(or_(User.username == form.username.data.strip(), User.email == form.email.data.strip().lower()), User.id != u.id).first()
        if duplicate:
            flash("Another account already uses that username or email.", "danger")
        else:
            u.username = form.username.data.strip(); u.full_name = form.full_name.data.strip()
            u.email = form.email.data.strip().lower(); u.role_id = form.role_id.data; u.is_active = form.is_active.data
            if form.password.data: u.set_password(form.password.data)
            db.session.commit()
            log_event("USER_UPDATED", f"Updated account {u.username}")
            flash("User updated.", "success")
            return redirect(url_for("users"))
    return render_template("user_form.html", form=form, heading="Edit user")

@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@permission_required("users.manage")
def user_toggle(user_id):
    u = db.get_or_404(User, user_id)
    if u.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
    else:
        u.is_active = not u.is_active
        db.session.commit()
        log_event("USER_STATUS_CHANGED", f"{u.username} active={u.is_active}")
        flash(f"Account {'activated' if u.is_active else 'deactivated'}.", "success")
    return redirect(url_for("users"))

@app.route("/roles")
@permission_required("roles.view")
def roles():
    role_list = Role.query.order_by(Role.name).all()
    permissions = Permission.query.order_by(Permission.code).all()
    mapping = {}
    for role in role_list:
        mapping[role.id] = {rp.permission_id for rp in RolePermission.query.filter_by(role_id=role.id).all()}
    return render_template("roles.html", roles=role_list, permissions=permissions, mapping=mapping)

@app.route("/roles/<int:role_id>/permissions", methods=["POST"])
@permission_required("roles.manage")
def role_permissions(role_id):
    role = db.get_or_404(Role, role_id)
    if role.name == "Administrator":
        flash("Administrator permissions are always unrestricted.", "info")
        return redirect(url_for("roles"))
    selected = {int(x) for x in request.form.getlist("permission_ids") if x.isdigit()}
    RolePermission.query.filter_by(role_id=role.id).delete()
    for pid in selected:
        if db.session.get(Permission, pid):
            db.session.add(RolePermission(role_id=role.id, permission_id=pid))
    db.session.commit()
    log_event("ROLE_PERMISSIONS_UPDATED", f"Updated permissions for {role.name}")
    flash("Role permissions saved.", "success")
    return redirect(url_for("roles"))

@app.route("/audit")
@permission_required("audit.view")
def audit():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(250).all()
    return render_template("audit.html", logs=logs)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm()
    if request.method == "GET":
        form.full_name.data = current_user.full_name
        form.email.data = current_user.email
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter(User.email == email, User.id != current_user.id).first():
            flash("That email address is already in use.", "danger")
        else:
            current_user.full_name = form.full_name.data.strip()
            current_user.email = email
            db.session.commit()
            log_event("PROFILE_UPDATED", "Updated profile")
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", form=form)

@app.route("/security", methods=["GET", "POST"])
@login_required
def security():
    password_form = PasswordForm()
    if request.method == "POST" and request.form.get("action") == "password":
        if password_form.validate_on_submit():
            if not current_user.check_password(password_form.current_password.data):
                flash("Current password is incorrect.", "danger")
            else:
                current_user.set_password(password_form.new_password.data)
                db.session.commit()
                log_event("PASSWORD_CHANGED", "Password changed")
                flash("Password changed successfully.", "success")
                return redirect(url_for("security"))
    return render_template("security.html", password_form=password_form)

@app.route("/mfa/setup")
@login_required
def mfa_setup():
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32()
        db.session.commit()
    uri = pyotp.TOTP(current_user.totp_secret).provisioning_uri(name=current_user.email, issuer_name="Secure IAM Minor Project")
    img = qrcode.make(uri)
    buf = BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
    return render_template("mfa_setup.html", secret=current_user.totp_secret)

@app.route("/mfa/qr")
@login_required
def mfa_qr():
    if not current_user.totp_secret: abort(404)
    uri = pyotp.TOTP(current_user.totp_secret).provisioning_uri(name=current_user.email, issuer_name="Secure IAM Minor Project")
    img = qrcode.make(uri); buf = BytesIO(); img.save(buf, format="PNG"); buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.route("/mfa/enable", methods=["POST"])
@login_required
def mfa_enable():
    code = request.form.get("otp", "").strip()
    if current_user.totp_secret and pyotp.TOTP(current_user.totp_secret).verify(code, valid_window=1):
        current_user.mfa_enabled = True; db.session.commit()
        log_event("MFA_ENABLED", "TOTP enabled")
        flash("Multi-factor authentication enabled.", "success")
    else:
        flash("Invalid code. Try the current six-digit code from your authenticator app.", "danger")
    return redirect(url_for("mfa_setup"))

@app.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    code = request.form.get("otp", "").strip()
    if current_user.totp_secret and pyotp.TOTP(current_user.totp_secret).verify(code, valid_window=1):
        current_user.mfa_enabled = False; current_user.totp_secret = None; db.session.commit()
        log_event("MFA_DISABLED", "TOTP disabled")
        flash("MFA disabled.", "success")
    else:
        flash("Invalid authenticator code.", "danger")
    return redirect(url_for("security"))

@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The requested page was not found."), 404

@app.errorhandler(CSRFError)
def handle_csrf(error):
    return render_template("error.html", code=400, message="Your form session expired. Go back and try again."), 400

# ---------------------------- Initial seed data ----------------------------
def seed_database():
    db.create_all()
    if Role.query.count() == 0:
        admin = Role(name="Administrator", description="Full system administration")
        manager = Role(name="Manager", description="Manage users and view security reports")
        employee = Role(name="Employee", description="Standard user access")
        db.session.add_all([admin, manager, employee]); db.session.commit()
    permission_data = [
        ("users.view", "View users"), ("users.manage", "Create, edit and deactivate users"),
        ("roles.view", "View roles"), ("roles.manage", "Manage role permissions"),
        ("audit.view", "View audit logs")
    ]
    for code, label in permission_data:
        if not Permission.query.filter_by(code=code).first():
            db.session.add(Permission(code=code, label=label))
    db.session.commit()
    admin_role = Role.query.filter_by(name="Administrator").first()
    manager_role = Role.query.filter_by(name="Manager").first()
    employee_role = Role.query.filter_by(name="Employee").first()
    if manager_role:
        for code in ["users.view", "users.manage", "roles.view", "audit.view"]:
            p = Permission.query.filter_by(code=code).first()
            if p and not RolePermission.query.filter_by(role_id=manager_role.id, permission_id=p.id).first():
                db.session.add(RolePermission(role_id=manager_role.id, permission_id=p.id))
    if employee_role:
        # Employees have dashboard and self-service access only.
        pass
    if not User.query.filter_by(username="admin").first():
        admin_user = User(username="admin", full_name="System Administrator", email="admin@example.com", role_id=admin_role.id)
        admin_user.set_password("Admin@12345")
        db.session.add(admin_user)
    if not User.query.filter_by(username="manager").first():
        manager_user = User(username="manager", full_name="Demo Manager", email="manager@example.com", role_id=manager_role.id)
        manager_user.set_password("Manager@123")
        db.session.add(manager_user)
    if not User.query.filter_by(username="employee").first():
        employee_user = User(username="employee", full_name="Demo Employee", email="employee@example.com", role_id=employee_role.id)
        employee_user.set_password("Employee@123")
        db.session.add(employee_user)
    db.session.commit()

with app.app_context():
    seed_database()

if __name__ == "__main__":
    app.run(debug=True)
