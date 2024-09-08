#!/usr/bin/env python3
"""Databased user session Module """

from models.base import Base


class UserSession(Base):
    """Session class"""
    def __init__(self, *args: list, **kwargs: dict):
        """Initializes the usersession  instance"""
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
