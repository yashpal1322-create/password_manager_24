from functools import wraps

from flask import session, redirect, url_for, flash

from app.models import User


# =========================================================
# GET CURRENT LOGGED-IN USER
# =========================================================

def get_current_user():
    """
    Return the currently logged-in user.

    Returns:
        User object if logged in.
        None if no user is logged in.
    """

    user_id = session.get("user_id")

    if not user_id:
        return None

    return User.query.get(user_id)


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(view_function):
    """
    Allow access only to authenticated users.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        user = get_current_user()

        if user is None:
            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            **kwargs
        )

    return wrapped_view


# =========================================================
# ADMIN REQUIRED
# =========================================================

def admin_required(view_function):
    """
    Allow access only to authenticated administrators.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        user = get_current_user()

        if user is None:
            flash(
                "Please login first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        if not user.is_admin:
            flash(
                "Administrator access required.",
                "danger"
            )

            return redirect(
                url_for("index")
            )

        return view_function(
            *args,
            **kwargs
        )

    return wrapped_view