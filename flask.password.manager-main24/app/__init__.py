import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from cryptography.fernet import Fernet


# Load .env
load_dotenv()


# Database
db = SQLAlchemy()


def create_app():

    app = Flask(__name__)

    # ==============================
    # BASIC CONFIGURATION
    # ==============================

    app.config["SECRET_KEY"] = os.getenv(
        "SECRET_KEY",
        "change-this-secret-key"
    )

    # SQLite database
    database_url = os.getenv(
        "DATABASE_URL",
        "sqlite:///passwords.db"
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


    # ==============================
    # SESSION CONFIGURATION
    # ==============================

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False


    # ==============================
    # FERNET ENCRYPTION
    # ==============================

    encryption_key = os.getenv("ENCRYPTION_KEY")

    if not encryption_key:

        raise RuntimeError(
            "ENCRYPTION_KEY is missing in .env"
        )

    try:

        # Validate encryption key
        Fernet(encryption_key)

    except Exception as error:

        raise RuntimeError(
            "Invalid ENCRYPTION_KEY in .env"
        ) from error

    app.config["ENCRYPTION_KEY"] = encryption_key


    # ==============================
    # EMAIL / OTP CONFIGURATION
    # ==============================

    app.config["MAIL_SERVER"] = os.getenv(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    app.config["MAIL_PORT"] = int(
        os.getenv("MAIL_PORT", "587")
    )

    app.config["MAIL_USE_TLS"] = (
        os.getenv(
            "MAIL_USE_TLS",
            "True"
        ).lower()
        == "true"
    )

    app.config["MAIL_USERNAME"] = os.getenv(
        "MAIL_USERNAME"
    )

    app.config["MAIL_PASSWORD"] = os.getenv(
        "MAIL_PASSWORD"
    )

    app.config["OTP_EXPIRY_MINUTES"] = int(
        os.getenv(
            "OTP_EXPIRY_MINUTES",
            "10"
        )
    )


    # ==============================
    # DATABASE INITIALIZATION
    # ==============================

    db.init_app(app)


    # ==============================
    # IMPORT MODELS
    # ==============================

    from app.models import (
        User,
        Password,
        AuditLog
    )


    # ==============================
    # CREATE DATABASE TABLES
    # ==============================

    with app.app_context():

        db.create_all()


    # ==============================
    # REGISTER BLUEPRINT
    # ==============================

    from app.routes import main

    app.register_blueprint(main)


    return app


# Create application
app = create_app()