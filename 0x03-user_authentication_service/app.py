#!/usr/bin/env python3
""" App Module"""

from flask import Flask, jsonify, request, abort
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """GET /
    Return:
        - The home page's payload.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def register_user() -> str:
    """Register a user using email and password."""
    email = request.form.get("email")
    password = request.form.get("password")

    # Check if both email and password are provided
    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    try:
        # Attempt to register the user
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 201
    except ValueError:
        # Handle the case where the email is already registered
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """Posts session id for a logged-in user."""
    email = request.form.get("email")
    password = request.form.get("password")

    # Check if login information is valid
    if not AUTH.valid_login(email, password):
        abort(401)

    try:
        # Create a new session for the user
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        # Store the session ID as a cookie in the response
        response.set_cookie("session_id", session_id)
        return response

    except Exception as e:
        # Handle any exceptions that may occur
        return jsonify({"message": str(e)}), 500


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """ Ends the users session"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
