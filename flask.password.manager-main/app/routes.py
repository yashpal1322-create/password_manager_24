import random
import secrets
import smtplib

from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from app import db
from app.models import (
    User,
    Password,
    AuditLog,
    PasswordReset
)

from app.crypto import (
    encrypt_password,
    decrypt_password
)


# ============================================================
# BLUEPRINT
# ============================================================

main = Blueprint(
    "main",
    __name__
)


# ============================================================
# LOGIN REQUIRED
# ============================================================

def login_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if not session.get("user_id"):

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("main.login")
            )

        return view(*args, **kwargs)

    return wrapped_view


# ============================================================
# ADMIN REQUIRED
# ============================================================

def admin_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if not session.get("user_id"):

            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("main.login")
            )

        if session.get("role") != "admin":

            flash(
                "Admin access required.",
                "danger"
            )

            return redirect(
                url_for("main.index")
            )

        return view(*args, **kwargs)

    return wrapped_view


# ============================================================
# AUDIT LOG
# ============================================================

def log_action(
    username,
    action,
    details=None,
    user_id=None
):

    try:

        log = AuditLog(
            username=username,
            action=action,
            details=details,
            user_id=user_id,
            ip_address=request.remote_addr
        )

        db.session.add(log)
        db.session.commit()

    except Exception:

        db.session.rollback()


# ============================================================
# SEND OTP EMAIL
# ============================================================

def send_otp_email(
    email,
    otp
):

    mail_username = current_app.config.get(
        "MAIL_USERNAME"
    )

    mail_password = current_app.config.get(
        "MAIL_PASSWORD"
    )

    mail_server = current_app.config.get(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    mail_port = current_app.config.get(
        "MAIL_PORT",
        587
    )

    mail_use_tls = current_app.config.get(
        "MAIL_USE_TLS",
        True
    )

    if not mail_username or not mail_password:

        return False

    message = EmailMessage()

    message["Subject"] = (
        "Password Manager - Master Password Reset OTP"
    )

    message["From"] = mail_username
    message["To"] = email

    message.set_content(
        f"""
Hello,

Your Password Manager Master Password reset OTP is:

{otp}

This OTP will expire in 10 minutes.

If you did not request a Master Password reset,
please ignore this email.

Password Manager
"""
    )

    try:

        if mail_use_tls:

            server = smtplib.SMTP(
                mail_server,
                mail_port
            )

            server.starttls()

        else:

            server = smtplib.SMTP(
                mail_server,
                mail_port
            )

        server.login(
            mail_username,
            mail_password
        )

        server.send_message(message)

        server.quit()

        return True

    except Exception as error:

        print(
            "Email error:",
            error
        )

        return False


# ============================================================
# HOME
# ============================================================

@main.route("/")
def home():

    if session.get("user_id"):

        if session.get("role") == "admin":

            return redirect(
                url_for("main.admin_vault")
            )

        return redirect(
            url_for("main.index")
        )

    return redirect(
        url_for("main.login")
    )


# ============================================================
# REGISTER
# ============================================================

@main.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if session.get("user_id"):

        return redirect(
            url_for("main.home")
        )

    if request.method == "POST":

        username = (
            request.form
            .get("username", "")
            .strip()
        )

        email = (
            request.form
            .get("email", "")
            .strip()
            .lower()
        )

        master_password = request.form.get(
            "master_password",
            ""
        )

        confirm_master_password = request.form.get(
            "confirm_master_password",
            ""
        )

        # -----------------------------
        # Validation
        # -----------------------------

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if not email:

            flash(
                "Email is required.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if len(master_password) < 8:

            flash(
                "Master Password must be at least 8 characters.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if master_password != confirm_master_password:

            flash(
                "Master Passwords do not match.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # -----------------------------
        # Existing username
        # -----------------------------

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:

            flash(
                "Username already exists.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # -----------------------------
        # Existing email
        # -----------------------------

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            flash(
                "Email already registered.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        # -----------------------------
        # Create user
        # -----------------------------

        user = User.create_user(
            username=username,
            email=email,
            master_password=master_password,
            role="user"
        )

        db.session.add(user)
        db.session.commit()

        log_action(
            username=username,
            user_id=user.id,
            action="REGISTER",
            details="New user account created."
        )

        flash(
            "Account created successfully. Please login.",
            "success"
        )

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@main.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get("user_id"):

        return redirect(
            url_for("main.home")
        )

    if request.method == "POST":

        username = (
            request.form
            .get("username", "")
            .strip()
        )

        master_password = request.form.get(
            "master_password",
            ""
        )

        user = User.query.filter_by(
            username=username
        ).first()

        # -----------------------------
        # Check credentials
        # -----------------------------

        if not user:

            log_action(
                username=username or "UNKNOWN",
                action="LOGIN_FAILED",
                details="Username not found."
            )

            flash(
                "Invalid username or Master Password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        if not check_password_hash(
            user.master_password_hash,
            master_password
        ):

            log_action(
                username=user.username,
                user_id=user.id,
                action="LOGIN_FAILED",
                details="Invalid Master Password."
            )

            flash(
                "Invalid username or Master Password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        # -----------------------------
        # Login success
        # -----------------------------

        session.clear()

        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role
        session["vault_unlocked"] = True

        log_action(
            username=user.username,
            user_id=user.id,
            action="LOGIN_SUCCESS",
            details="User logged in and vault unlocked."
        )

        if user.role == "admin":

            return redirect(
                url_for("main.admin_vault")
            )

        return redirect(
            url_for("main.index")
        )

    return render_template(
        "login.html"
    )


# ============================================================
# USER VAULT
# ============================================================

@main.route("/vault")
@login_required
def index():

    user_id = session.get(
        "user_id"
    )

    # Vault must be unlocked
    if not session.get("vault_unlocked"):

        flash(
            "Please login to unlock your vault.",
            "warning"
        )

        return redirect(
            url_for("main.login")
        )

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        session.clear()

        return redirect(
            url_for("main.login")
        )

    passwords = Password.query.filter_by(
        user_id=user.id
    ).order_by(
        Password.id.desc()
    ).all()

    return render_template(
        "index.html",
        user=user,
        passwords=passwords
    )


# ============================================================
# ADD PASSWORD
# ============================================================

@main.route(
    "/password/add",
    methods=["GET", "POST"]
)
@login_required
def add_password():

    if not session.get("vault_unlocked"):

        flash(
            "Vault is locked.",
            "warning"
        )

        return redirect(
            url_for("main.login")
        )

    if request.method == "POST":

        name = (
            request.form
            .get("name", "")
            .strip()
        )

        username = (
            request.form
            .get("username", "")
            .strip()
        )

        password = request.form.get(
            "password",
            ""
        )

        website = (
            request.form
            .get("website", "")
            .strip()
        )

        notes = (
            request.form
            .get("notes", "")
            .strip()
        )

        if not name:

            flash(
                "Password name is required.",
                "danger"
            )

            return render_template(
                "add_password.html"
            )

        if not username:

            flash(
                "Username is required.",
                "danger"
            )

            return render_template(
                "add_password.html"
            )

        if not password:

            flash(
                "Password is required.",
                "danger"
            )

            return render_template(
                "add_password.html"
            )

        encrypted = encrypt_password(
            password
        )

        saved_password = Password(
            user_id=session["user_id"],
            name=name,
            username=username,
            encrypted_password=encrypted,
            website=website or None,
            notes=notes or None
        )

        db.session.add(
            saved_password
        )

        db.session.commit()

        log_action(
            username=session["username"],
            user_id=session["user_id"],
            action="PASSWORD_ADDED",
            details=f"Password entry '{name}' added."
        )

        flash(
            "Password saved successfully.",
            "success"
        )

        return redirect(
            url_for("main.index")
        )

    return render_template(
        "add_password.html"
    )


# ============================================================
# VIEW PASSWORD
# ============================================================

@main.route(
    "/password/<int:password_id>"
)
@login_required
def view_password(password_id):

    if not session.get("vault_unlocked"):

        flash(
            "Vault is locked.",
            "warning"
        )

        return redirect(
            url_for("main.login")
        )

    password = Password.query.filter_by(
        id=password_id,
        user_id=session["user_id"]
    ).first()

    if not password:

        flash(
            "Password entry not found.",
            "danger"
        )

        return redirect(
            url_for("main.index")
        )

    try:

        decrypted_password = decrypt_password(
            password.encrypted_password
        )

    except Exception:

        flash(
            "Unable to decrypt this password.",
            "danger"
        )

        return redirect(
            url_for("main.index")
        )

    return render_template(
        "view_password.html",
        password=password,
        decrypted_password=decrypted_password
    )


# ============================================================
# DELETE PASSWORD
# ============================================================

@main.route(
    "/password/delete/<int:password_id>",
    methods=["POST"]
)
@login_required
def delete_password(password_id):

    password = Password.query.filter_by(
        id=password_id,
        user_id=session["user_id"]
    ).first()

    if not password:

        flash(
            "Password entry not found.",
            "danger"
        )

        return redirect(
            url_for("main.index")
        )

    password_name = password.name

    db.session.delete(
        password
    )

    db.session.commit()

    log_action(
        username=session["username"],
        user_id=session["user_id"],
        action="PASSWORD_DELETED",
        details=f"Password entry '{password_name}' deleted."
    )

    flash(
        "Password deleted successfully.",
        "success"
    )

    return redirect(
        url_for("main.index")
    )


# ============================================================
# FORGOT MASTER PASSWORD
# ============================================================

@main.route(
    "/forgot-master-password",
    methods=["GET", "POST"]
)
def forgot_master_password():

    if request.method == "POST":

        email = (
            request.form
            .get("email", "")
            .strip()
            .lower()
        )

        user = User.query.filter_by(
            email=email
        ).first()

        # Do not reveal whether email exists
        if not user:

            flash(
                "If this email is registered, an OTP will be sent.",
                "info"
            )

            return redirect(
                url_for(
                    "main.forgot_master_password"
                )
            )

        # -----------------------------
        # Delete old reset requests
        # -----------------------------

        PasswordReset.query.filter_by(
            user_id=user.id,
            used=False
        ).delete()

        # -----------------------------
        # Generate OTP
        # -----------------------------

        otp = f"{random.randint(0, 999999):06d}"

        otp_hash = generate_password_hash(
            otp
        )

        expiry_minutes = current_app.config.get(
            "OTP_EXPIRY_MINUTES",
            10
        )

        reset = PasswordReset(
            user_id=user.id,
            email=user.email,
            otp_hash=otp_hash,
            expires_at=datetime.utcnow()
            + timedelta(
                minutes=expiry_minutes
            )
        )

        db.session.add(reset)
        db.session.commit()

        # -----------------------------
        # Send email
        # -----------------------------

        email_sent = send_otp_email(
            user.email,
            otp
        )

        if not email_sent:

            db.session.delete(
                reset
            )

            db.session.commit()

            log_action(
                username=user.username,
                user_id=user.id,
                action="PASSWORD_RESET_REQUESTED",
                details="OTP email could not be sent."
            )

            flash(
                "Unable to send OTP email. Check mail configuration.",
                "danger"
            )

            return redirect(
                url_for(
                    "main.forgot_master_password"
                )
            )

        log_action(
            username=user.username,
            user_id=user.id,
            action="PASSWORD_RESET_REQUESTED",
            details="Master Password reset OTP sent."
        )

        session["reset_user_id"] = user.id
        session["reset_id"] = reset.id

        flash(
            "OTP has been sent to your registered email.",
            "success"
        )

        return redirect(
            url_for("main.verify_otp")
        )

    return render_template(
        "forgot_master.html"
    )


# ============================================================
# VERIFY OTP
# ============================================================
@main.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    reset_id = session.get("reset_id")
    user_id = session.get("reset_user_id")

    # -----------------------------
    # Check session
    # -----------------------------
    if not reset_id or not user_id:
        flash("Please request a new OTP.", "warning")
        return redirect(url_for("main.forgot_master_password"))

    reset = PasswordReset.query.filter_by(
        id=reset_id,
        user_id=user_id,
        used=False
    ).first()

    if not reset:
        flash("Invalid or expired reset request.", "danger")

        session.pop("reset_id", None)
        session.pop("reset_user_id", None)

        return redirect(url_for("main.forgot_master_password"))

    user = db.session.get(User, user_id)

    # -----------------------------
    # Expiry check
    # -----------------------------
    if datetime.utcnow() > reset.expires_at:

        if user:
            log_action(
                username=user.username,
                user_id=user.id,
                action="OTP_EXPIRED",
                details="Password reset OTP expired."
            )

        reset.used = True
        db.session.commit()

        session.pop("reset_id", None)
        session.pop("reset_user_id", None)

        flash("OTP has expired. Please request a new OTP.", "danger")

        return redirect(url_for("main.forgot_master_password"))

    # -----------------------------
    # POST: Verify OTP
    # -----------------------------
    if request.method == "POST":

        otp = request.form.get("otp", "").strip()

        # 🔒 Attempt limit
        if reset.attempts >= 5:
            reset.used = True
            db.session.commit()

            if user:
                log_action(
                    username=user.username,
                    user_id=user.id,
                    action="OTP_BLOCKED",
                    details="Too many OTP attempts."
                )

            flash("Too many attempts. Request new OTP.", "danger")

            session.pop("reset_id", None)
            session.pop("reset_user_id", None)

            return redirect(url_for("main.forgot_master_password"))

        # 🔢 Validate OTP format
        if not otp or len(otp) != 6:
            flash("Enter a valid 6-digit OTP.", "danger")
            return render_template("verify_otp.html")

        # ❌ Invalid OTP
        if not check_password_hash(reset.otp_hash, otp):

            reset.attempts += 1
            db.session.commit()

            if user:
                log_action(
                    username=user.username,
                    user_id=user.id,
                    action="OTP_FAILED",
                    details="Invalid OTP entered."
                )

            flash("Invalid OTP", "danger")
            return render_template("verify_otp.html")

        # ✅ OTP verified
        reset.verified = True
        db.session.commit()

        if user:
            log_action(
                username=user.username,
                user_id=user.id,
                action="OTP_VERIFIED",
                details="Password reset OTP verified."
            )

        return redirect(url_for("main.reset_master_password"))

    # -----------------------------
    # GET request
    # -----------------------------
    return render_template("verify_otp.html")

# ============================================================
# RESET MASTER PASSWORD
# ============================================================

@main.route(
    "/reset-master-password",
    methods=["GET", "POST"]
)
def reset_master_password():

    reset_id = session.get(
        "reset_id"
    )

    user_id = session.get(
        "reset_user_id"
    )

    if not reset_id or not user_id:

        flash(
            "Invalid password reset session.",
            "danger"
        )

        return redirect(
            url_for(
                "main.forgot_master_password"
            )
        )

    reset = PasswordReset.query.filter_by(
        id=reset_id,
        user_id=user_id,
        used=False,
        verified=True
    ).first()

    if not reset:

        flash(
            "Please verify the OTP first.",
            "danger"
        )

        return redirect(
            url_for(
                "main.forgot_master_password"
            )
        )

    # -----------------------------
    # Check expiry again
    # -----------------------------

    if datetime.utcnow() > reset.expires_at:

        reset.used = True

        db.session.commit()

        session.pop(
            "reset_id",
            None
        )

        session.pop(
            "reset_user_id",
            None
        )

        flash(
            "Password reset session expired.",
            "danger"
        )

        return redirect(
            url_for(
                "main.forgot_master_password"
            )
        )

    if request.method == "POST":

        new_password = request.form.get(
            "new_master_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_master_password",
            ""
        )

        if len(new_password) < 8:

            flash(
                "Master Password must be at least 8 characters.",
                "danger"
            )

            return render_template(
                "reset_master.html"
            )

        if new_password != confirm_password:

            flash(
                "Master Passwords do not match.",
                "danger"
            )

            return render_template(
                "reset_master.html"
            )

        user = db.session.get(
            User,
            user_id
        )

        if not user:

            flash(
                "User account not found.",
                "danger"
            )

            return redirect(
                url_for("main.login")
            )

        # -----------------------------
        # Update Master Password
        # -----------------------------

        user.master_password_hash = (
            generate_password_hash(
                new_password
            )
        )

        reset.used = True

        db.session.commit()

        log_action(
            username=user.username,
            user_id=user.id,
            action="MASTER_PASSWORD_RESET",
            details="Master Password successfully reset."
        )

        # -----------------------------
        # Clear recovery session
        # -----------------------------

        session.pop(
            "reset_id",
            None
        )

        session.pop(
            "reset_user_id",
            None
        )

        flash(
            "Master Password reset successfully. Please login.",
            "success"
        )

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "reset_master.html"
    )


# ============================================================
# ADMIN VAULT
# ============================================================

@main.route(
    "/admin/vault"
)
@admin_required
def admin_vault():

    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    users = User.query.order_by(
        User.id.asc()
    ).all()

    return render_template(
        "admin_vault.html",
        logs=logs,
        users=users
    )


# ============================================================
# ADMIN USERS
# ============================================================

@main.route(
    "/admin/users"
)
@admin_required
def admin_users():

    users = User.query.order_by(
        User.id.asc()
    ).all()

    return render_template(
        "admin_users.html",
        users=users
    )


# ============================================================
# LOGOUT
# ============================================================

@main.route("/logout")
@login_required
def logout():

    username = session.get(
        "username",
        "UNKNOWN"
    )

    user_id = session.get(
        "user_id"
    )

    log_action(
        username=username,
        user_id=user_id,
        action="LOGOUT",
        details="User logged out."
    )

    session.clear()

    flash(
        "You have been logged out.",
        "info"
    )

    return redirect(
        url_for("main.login")
    )