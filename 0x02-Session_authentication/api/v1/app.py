#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os

from api.v1.auth.auth import Auth
from api.v1.views import app_views
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.auth.session_db_auth import SessionDBAuth


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None
auth_type = getenv('AUTH_TYPE', 'auth')
if auth_type == 'auth':
    auth = Auth()
if auth_type == 'basic_auth':
    auth = BasicAuth()
if auth_type == 'session_auth':
    auth = SessionAuth()
if auth_type == 'SessionExpAuth':
    auth = session_exp_auth()
if auth_type == 'SessionDBAuth':
    auth = session_db_auth()


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """ Unauthorized handler
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """ Forbidden handler
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def authenticate_user():
    """Authenticates a user before processing a request."""
    if not auth:
        return  # If `auth` is not defined, skip authentication.

    # Define excluded paths where authentication is not required
    excluded_paths = [
        '/api/v1/status/',
        '/api/v1/unauthorized/',
        '/api/v1/forbidden/',
        '/api/v1/auth_session/login/',
    ]

    # Check if the current request path requires authentication
    if not auth.require_auth(request.path, excluded_paths):
        return  # If authentication is not required, proceed with the request.

    # Use the correct method based on the auth class
    if isinstance(auth, SessionAuth):
        auth_session = auth.session_cookie(request)
        user = auth.current_user(request) if auth_session else None
        request.current_user = user
    else:
        user = auth.current_user(request)
        request.current_user = user

    # Abort with 401 if the Authorization header is missing
    if not request.current_user:
        abort(401)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
