"""Authentication & authorisation helpers for the Flask BFF.

Session/token extraction plus the four route decorators. Page decorators
(`login_required`, `admin_role_required`) redirect; their `/api` counterparts
(`api_login_required`, `api_admin_role_required`) return JSON errors. The redirect
targets are resolved by endpoint name at request time, so these live independently
of where the routes are defined.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from http import HTTPStatus
from typing import Any, cast

import jwt
from flask import jsonify, redirect, session, url_for

logger = logging.getLogger(__name__)


def get_access_token() -> str | None:
    """Overly simple method for fetching an access token from the user's session. All validation will be handled at the
    service receiving this access_token - all we are validating is that there is one and that it hasn't expired

    Returns access_token if its present AND not expired. None otherwise."""

    if "user" not in session:
        logger.info("user not found in session.")
        return None

    user = session["user"]
    if user is None or "access_token" not in user:
        logger.info("access_token not found in user.")
        return None

    access_token = user["access_token"]
    if not access_token:
        logger.info("access_token appears to be empty.")
        return None

    # access_token should come paired with expires_at (the returned metadata from OAuth2)
    if "expires_at" not in user:
        logger.error("No expires_at was returned with access_token.")
        return None

    try:
        exp_time = datetime.fromtimestamp(float(user["expires_at"]), tz=UTC)
        if exp_time < datetime.now(tz=UTC):
            logger.info(f"User access_token expired at {exp_time}.")
            return None
    except Exception as exc:
        logger.error("Exception attempting to decode user expires_at.", exc_info=exc)
        return None

    return access_token


def get_username_from_session() -> str | None:
    """
    Extracts the username from the OAuth2 session token.

    Returns:
        Username string if user is logged in, None otherwise.
        Tries common OAuth2 fields in order of preference
    """
    if "user" not in session:
        return None

    user_info = session["user"].get("userinfo", {})

    return user_info.get("name")


def login_required[F: Callable[..., object]](f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        access_token = get_access_token()
        if access_token is None:
            return redirect(url_for("login"))

        return f(*args, access_token=access_token, **kwargs)

    return cast(F, decorated)


def get_permissions() -> list[str] | None:
    if "user" not in session:
        return None

    user = session["user"]

    if "access_token" not in user:
        return None

    encoded_jwt = user["access_token"]
    decoded_jwt = jwt.decode(encoded_jwt, options={"verify_signature": False})

    if "permissions" not in decoded_jwt:
        return None

    return decoded_jwt["permissions"]


def admin_role_required[F: Callable[..., object]](f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        permissions = get_permissions()
        if not permissions or "admin:all" not in permissions:
            return redirect(url_for("login_or_home_page"))

        return f(*args, **kwargs)

    return cast(F, decorated)


def api_login_required[F: Callable[..., object]](f: F) -> F:
    """Like login_required, but for /api endpoints: returns 401 JSON instead of redirecting to login."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        access_token = get_access_token()
        if access_token is None:
            return jsonify({"error": "unauthenticated"}), HTTPStatus.UNAUTHORIZED

        return f(*args, access_token=access_token, **kwargs)

    return cast(F, decorated)


def api_admin_role_required[F: Callable[..., object]](f: F) -> F:
    """Like admin_role_required, but for /api endpoints: returns 403 JSON instead of redirecting."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        permissions = get_permissions()
        if not permissions or "admin:all" not in permissions:
            return jsonify({"error": "forbidden"}), HTTPStatus.FORBIDDEN

        return f(*args, **kwargs)

    return cast(F, decorated)
