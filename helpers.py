from flask import request, redirect, session
from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(
                f"/login{'?redirect_to={request.path}' if request.path != '/' else ''}"
            )
        return f(*args, **kwargs)

    return decorated_function


def logged_out_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is not None:
            return redirect("/")
        return f(*args, **kwargs)

    return decorated_function
