#!/usr/bin/env python3
""" App Module"""

from flask import Flask, jsonify, request
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
