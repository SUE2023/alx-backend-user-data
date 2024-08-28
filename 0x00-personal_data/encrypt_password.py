#!/usr/bin/env python3
""" Encryption Function"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes password using a random salt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates that the provided password matches the hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
