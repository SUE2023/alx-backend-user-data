#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session

from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a new user to the database. """
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            self._session.add(new_user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            new_user = None
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Finds a user based on a set of filters.

        Args:
            **kwargs: Arbitrary keyword arguments corresponding to User
            attributes.

        Returns:
            User: The first user that matches the filter criteria.

        Raises:
            InvalidRequestError: If any of the provided query arguments are
            invalid.
            NoResultFound: If no user is found matching the filter criteria.
        """
        # Check if all kwargs correspond to valid attributes of the User class
        for key in kwargs.keys():
            if not hasattr(User, key):
                raise InvalidRequestError(f"Invalid attribute: {key}")

        # Query the first user matching the given filters
        result = self._session.query(User).filter_by(**kwargs).first()

        # Raise NoResultFound if no user is found
        if result is None:
            raise NoResultFound()

        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update the user's attributes and commit changes to the database.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Arbitrary keyword arguments representing the attributes
            to update.

        Raises:
            ValueError: If argument doesn't correspond to valid user attribute.
        """
        try:
            # Use find_user_by to locate the user by user_id
            user = self.find_user_by(id=user_id)

            # Update user attributes based on kwargs
            for key, value in kwargs.items():
                # Check if the user has the given attribute
                if not hasattr(user, key):
                    raise ValueError(f"Invalid attribute: {key}")
                setattr(user, key, value)  # Update the attribute

                # Commit the changes to the database
                self._session.commit()

        except NoResultFound:
            raise ValueError("User not found")
        except InvalidRequestError:
            raise ValueError("Invalid request")
