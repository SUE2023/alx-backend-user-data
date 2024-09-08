#!/usr/bin/env python3
"""Module of session authenticating views.
"""
import os
from typing import Tuple
from flask import abort, jsonify, request
from models.user import User
from api.v1.views import app_views


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """POST /api/v1/auth_session/login
    Handles user login using session authentication.
    Return:
      - JSON representation of a User object or an error message.
    """
    # Retrieve email and password from the form data
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    # Validate email and password
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Find the user by email
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    # Check if user exists and password is valid
    if users and users[0].is_valid_password(password):
        from api.v1.app import auth
        session_id = auth.create_session(getattr(users[0], 'id'))
        response = jsonify(users[0].to_json())
        response.set_cookie(os.getenv("SESSION_NAME"), session_id)
        return response

    # Return error if no user found or invalid password
    error_msg = {
        "error": "wrong password" if users else "no user found for this email"}
    status_code = 401 if users else 404
    return jsonify(error_msg), status_code


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """DELETE /api/v1/auth_session/logout
    Handles user logout by destroying the session.
    Return:
      - An empty JSON object on successful logout.
    """
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({})
