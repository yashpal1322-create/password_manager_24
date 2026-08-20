from datetime import datetime

from werkzeug.security import generate_password_hash

from app import db


# ============================================================
# USER MODEL
# ============================================================

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    # Master Password ka HASH store hoga.
    # Original Master Password database mein store nahi hoga.
    master_password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="user"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )


    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    passwords = db.relationship(
        "Password",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan"
    )

    audit_logs = db.relationship(
        "AuditLog",
        backref="user",
        lazy=True
    )


    # --------------------------------------------------------
    # Create User
    # --------------------------------------------------------

    @staticmethod
    def create_user(
        username,
        email,
        master_password,
        role="user"
    ):

        user = User(
            username=username,
            email=email,
            master_password_hash=
                generate_password_hash(
                    master_password
                ),
            role=role
        )

        return user


    # --------------------------------------------------------
    # Admin Check
    # --------------------------------------------------------

    def is_admin(self):

        return self.role == "admin"


# ============================================================
# PASSWORD MODEL
# ============================================================

class Password(db.Model):

    __tablename__ = "passwords"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # Every password belongs to one user.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    name = db.Column(
        db.String(255),
        nullable=False
    )

    username = db.Column(
        db.String(255),
        nullable=False
    )

    # Encrypted using Fernet.
    encrypted_password = db.Column(
        db.Text,
        nullable=False
    )

    website = db.Column(
        db.String(500),
        nullable=True
    )

    notes = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )


# ============================================================
# AUDIT LOG MODEL
# ============================================================

class AuditLog(db.Model):

    __tablename__ = "audit_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # User related to the activity.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    username = db.Column(
        db.String(150),
        nullable=False
    )

    action = db.Column(
        db.String(100),
        nullable=False
    )

    details = db.Column(
        db.Text,
        nullable=True
    )

    ip_address = db.Column(
        db.String(100),
        nullable=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )


# ============================================================
# PASSWORD RESET / OTP MODEL
# ============================================================

class PasswordReset(db.Model):

    __tablename__ = "password_resets"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    email = db.Column(
        db.String(255),
        nullable=False
    )

    # OTP ka hash store karna better hai.
    otp_hash = db.Column(
        db.String(255),
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    used = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )
    
    attempts = db.Column(
    db.Integer,
    default=0,
    nullable=False)