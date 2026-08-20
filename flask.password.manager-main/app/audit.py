from flask import request

from app import db
from app.models import AuditLog


def log_action(
    username,
    action,
    details=None,
    user_id=None
):
    """
    Save an activity to the audit log.

    This file is kept separate so audit logging
    can be reused from different parts of the application.
    """

    try:

        ip_address = request.remote_addr

    except RuntimeError:

        # request context available na ho
        ip_address = None


    log = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        details=details,
        ip_address=ip_address
    )

    db.session.add(log)

    try:

        db.session.commit()

    except Exception:

        db.session.rollback()

        return False

    return True