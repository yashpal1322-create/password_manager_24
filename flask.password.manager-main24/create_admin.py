from getpass import getpass

from app import app, db
from app.models import User


def create_admin():

    print("=" * 50)
    print("        PASSWORD MANAGER ADMIN SETUP")
    print("=" * 50)

    username = input(
        "Enter admin username: "
    ).strip()

    email = input(
        "Enter admin email: "
    ).strip().lower()

    if not username or not email:

        print(
            "\nUsername and email are required."
        )

        return

    # Check existing username
    existing_username = User.query.filter_by(
        username=username
    ).first()

    if existing_username:

        print(
            "\nUsername already exists."
        )

        return

    # Check existing email
    existing_email = User.query.filter_by(
        email=email
    ).first()

    if existing_email:

        print(
            "\nEmail already exists."
        )

        return

    # Password input
    master_password = getpass(
        "Enter admin Master Password: "
    )

    confirm_password = getpass(
        "Confirm admin Master Password: "
    )

    if len(master_password) < 8:

        print(
            "\nMaster Password must be at least 8 characters."
        )

        return

    if master_password != confirm_password:

        print(
            "\nMaster Passwords do not match."
        )

        return

    # Create admin
    admin = User.create_user(
        username=username,
        email=email,
        master_password=master_password,
        role="admin"
    )

    db.session.add(admin)
    db.session.commit()

    print("\n" + "=" * 50)
    print("ADMIN ACCOUNT CREATED SUCCESSFULLY")
    print("=" * 50)

    print(
        f"Username : {username}"
    )

    print(
        f"Email    : {email}"
    )

    print(
        "Role     : admin"
    )

    print("=" * 50)


if __name__ == "__main__":

    with app.app_context():

        create_admin()