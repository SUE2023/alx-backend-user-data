#!/usr/bin/env python3
"""Basic authentication module for the API.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar, Optional

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class.
    """

    def extract_base64_authorization_header(self, authorization_header: Optional[str]) -> Optional[str]:
        """Extracts the Base64 part of the Authorization header for Basic Authentication.

        Args:
            authorization_header (str): The authorization header.

        Returns:
            Optional[str]: The Base64 part of the Authorization header or None.
        """
        if not isinstance(authorization_header, str):
            return None

        # Check if the header follows the 'Basic <token>' format
        match = re.fullmatch(r'Basic (?P<token>.+)', authorization_header.strip())
        return match.group('token') if match else None

    def decode_base64_authorization_header(self, base64_authorization_header: Optional[str]) -> Optional[str]:
        """Decodes a base64-encoded authorization header.

        Args:
            base64_authorization_header (str): The base64 encoded header.

        Returns:
            Optional[str]: The decoded string or None if decoding fails.
        """
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header, validate=True)
            return decoded_bytes.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """Extracts user credentials from a base64-decoded authorization header.

        Args:
            decoded_base64_authorization_header (str): The decoded header.

        Returns:
            Tuple[Optional[str], Optional[str]]: The user email and password.
        """
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        # Check for the '<user>:<password>' format
        match = re.fullmatch(r'(?P<user>[^:]+):(?P<password>.+)', decoded_base64_authorization_header.strip())
        if match:
            return match.group('user'), match.group('password')
        return None, None

    def user_object_from_credentials(self, user_email: Optional[str], user_pwd: Optional[str]) -> Optional[TypeVar('User')]:
        """Retrieves a user based on the user's authentication credentials.

        Args:
            user_email (str): The user's email address.
            user_pwd (str): The user's password.

        Returns:
            Optional[TypeVar('User')]: The User object or None.
        """
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({'email': user_email})
            if not users or not users[0].is_valid_password(user_pwd):
                return None
            return users[0]
        except Exception:
            return None

    def current_user(self, request=None) -> Optional[TypeVar('User')]:
        """Retrieves the user from a request.

        Args:
            request (Flask request object): The current request.

        Returns:
            Optional[TypeVar('User')]: The User object or None.
        """
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None

        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        if not b64_auth_token:
            return None

        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        if not auth_token:
            return None

        email, password = self.extract_user_credentials(auth_token)
        if not email or not password:
            return None

        return self.user_object_from_credentials(email, password)
