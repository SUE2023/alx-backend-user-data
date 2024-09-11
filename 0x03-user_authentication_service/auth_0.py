#!/usr/bin/env python3
"""Hash password method """
import bcrypt


def _hash_password(password: str) -> bytes:
    # Hashing a password
    password = b"my_secure_password"  # Password must be in bytes
    salt = bcrypt.gensalt()  # Generate a salt
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password, salt)
    print(f"Hashed password: {hashed_password}")

    # Verifying a password
    password_attempt = b"my_secure_password"
    # Check if the hashed passwords match
    is_correct = bcrypt.checkpw(password_attempt, hashed_password)

    if is_correct:
        print("Password is correct!")
    else:
        print("Password is incorrect!")
