#!/usr/bin/env python3
"""Session Auth Class"""

from uuid import uuid4
from flask import request

from .auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Session authentication class."""
    # Class attribute to store user_id mapped by session_id
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a Session ID for the user.

        Args:
            user_id (str): The user's ID.

        Returns:
            str: The generated Session ID or None if user_id is invalid.
        """
        # Return None if user_id is None or not a string
        if user_id is None or not isinstance(user_id, str):
            return None

        # Generate a new Session ID
        session_id = str(uuid4())

        # Store the mapping of session_id to user_id
        self.user_id_by_session_id[session_id] = user_id

        # Return the created session_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieves a User ID based on a given Session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            str: User ID associated with the session ID, or None if not found.
        """
        # Return None if session_id is None or not a string
        if session_id is None or not isinstance(session_id, str):
            return None

        # Retrieve the User ID using the session_id
        # Using .get() is preferred over direct dictionary access because it
        # avoids raising a KeyError if the key does not exist.
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Returns a User instance based on a cookie value."""
        # Retrieve the session ID from the cookie
        session_id = self.session_cookie(request)
        if session_id is None:
            return None  # Return None if no session ID is found

        # Retrieve the User ID associated with the session ID
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:  # Return None if no user ID
            return None  # is associated with the session ID

        # Retrieve and return the User instance based on the User ID
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Method that deletes the user session / logout."""
        # Return False if the request is None
        if request is None:
            return False

        # Retrieve the session ID from the cookie
        session_id = self.session_cookie(request)

        # Return False if the session ID is not found in the request
        if session_id is None:
            return False

        # Retrieve the User ID associated with the session ID
        user_id = self.user_id_for_session_id(session_id)

        # Return False if the session ID is not linked to any User ID
        if user_id is None:
            return False

        # Delete the session ID from the dictionary
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
            return True

        # In case the session ID is not found, return False
        return False
