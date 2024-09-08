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
    ]

    # Check if the current request path requires authentication
    if not auth.require_auth(request.path, excluded_paths):
        return  # If authentication is not required, proceed with the request.

    # Get the Authorization header and current user
    auth_header = auth.authorization_header(request)
    user = auth.current_user(request)

    # Get the Sessions cookies and current user
    auth_session = auth.session_cookie(request)
    session_user = session.current_user(request)

    # Assign the authenticated user to request.current_user
    request.current_user = user if user else session_user

    # Abort with 401 if the Authorization header is missing
    if auth_header is None and auth_session is None:
        abort(401)

    # Abort with 403 if the user is not authenticated
    if request.current_user is None:
        abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
    app.run(debug=True)
