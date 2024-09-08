#!/usr/bin/env python3
""" Module for API authentication.
"""

from flask import request
import re
from typing import List, Optional, TypeVar


class Auth:
    """Authentication class.
    """

    def require_auth(
            self, path: Optional[str], excluded_paths: Optional[List[str]]
            ) -> bool:
        """Checks if a path requires authentication.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): List of paths that do not require
            authentication.

        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if path is None or excluded_paths is None:
            # If no path or excluded paths are provided, require authentication
            return True

        # Normalize the path by removing trailing slashes for consistency
        normalized_path = path.rstrip('/')

        # Process excluded paths, removing trailing slashes and handling
        # wildcard patterns
        patterns = [
            re.escape(exclusion.rstrip('/')).replace(r'\*', '.*') + r'/?'
            for exclusion in excluded_paths
        ]

        # Check if the path matches any of the patterns
        for pattern in patterns:
            if re.fullmatch(pattern, normalized_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets the current user from the request.
        """
        return None

    def session_cookie(self, request=None) -> str:
        """Gets the value of the cookie named SESSION_NAME.
        """
        if request is not None:
            cookie_name = os.getenv('SESSION_NAME')
            return request.cookies.get(cookie_name)
