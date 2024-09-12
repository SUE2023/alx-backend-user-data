#!/usr/bin/env python3
""" App Module"""

from flask import Flask, jsonify, request, abort, redirect
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


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """Get the user's profile."""
    # Get the session ID from the cookies
    session_id = request.cookies.get("session_id")
    # Retrieve the user from the session ID
    user = AUTH.get_user_from_session_id(session_id)
    # Check if the user exists
    if user is not None:
        return jsonify({"email": user.email}), 200
    else:
        # Respond with a 403 status code if the user does not exist
        # or session ID is invalid
        abort(403)


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """Resets password and provides a reset token."""
    # Get the email from the form data
    email = request.form.get("email")

    # Check if the email is registered
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        # Respond with a 403 status code if the email is not registered
        abort(403)


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> str:
    """Updates the user's password given a reset token."""
    # Get the form data from the request
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        # Attempt to update the password using the reset token
        AUTH.update_password(reset_token, new_password)
        # Return a success response if the update is successful
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        # If the reset token is invalid, respond with a 403 error code
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
