import os

from cryptography.fernet import Fernet


# ============================================================
# GET ENCRYPTION KEY
# ============================================================

ENCRYPTION_KEY = os.getenv(
    "ENCRYPTION_KEY"
)

if not ENCRYPTION_KEY:
    raise RuntimeError(
        "ENCRYPTION_KEY is missing in .env"
    )


# ============================================================
# CREATE FERNET CIPHER
# ============================================================

try:

    cipher = Fernet(
        ENCRYPTION_KEY.encode()
        if isinstance(ENCRYPTION_KEY, str)
        else ENCRYPTION_KEY
    )

except Exception as error:

    raise RuntimeError(
        "Invalid ENCRYPTION_KEY in .env"
    ) from error


# ============================================================
# ENCRYPT PASSWORD
# ============================================================

def encrypt_password(password):

    if password is None:
        raise ValueError(
            "Password cannot be None."
        )

    if not isinstance(password, str):
        password = str(password)

    encrypted = cipher.encrypt(
        password.encode("utf-8")
    )

    return encrypted.decode("utf-8")


# ============================================================
# DECRYPT PASSWORD
# ============================================================

def decrypt_password(encrypted_password):

    if not encrypted_password:
        raise ValueError(
            "Encrypted password is empty."
        )

    if not isinstance(
        encrypted_password,
        str
    ):
        encrypted_password = str(
            encrypted_password
        )

    decrypted = cipher.decrypt(
        encrypted_password.encode("utf-8")
    )

    return decrypted.decode("utf-8")