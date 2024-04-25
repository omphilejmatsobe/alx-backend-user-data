#!/usr/bin/env python3
"""
Module for password encryption and user data registration
"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from db import DB
from user import User


def _hash_password(password: str) -> str:
    """ method that takes in a password string arguments and returns bytes """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """ return a string representation of a new UUID """
    return str(uuid4())


class Auth:
    """
    Class Auth to interact with the authentication database.
    """

    def __init__(self):
        """ Auth class constructor """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ takes email and password string arguments and
            return a User"""

        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            pwd = _hash_password(password)
            user = self._db.add_user(email, pwd)
            return user
        else:
            raise ValueError('User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """ credentials validation, return a boolean """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        else:
            return bcrypt.checkpw(password=password.encode('utf-8'),
                                  hashed_password=user.hashed_password)

    def create_session(self, email: str) -> str:
        """
        Takes an email string argument and returns the session ID as a string
        """

        try:
            session_user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            session_id = _generate_uuid()
            self._db.update_user(session_user.id, session_id=session_id)
            return session_id

    def get_user_from_session_id(self, session_id: str) -> str:
        """ takes a single session_id string argument and returns
        the corresponding User or None """

        try:
            cor_user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return cor_user

    def destroy_session(self, user_id: int) -> None:
        """ Takes a single user_id integer argument and returns None """
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ Generates a UUID and updates the user’s reset_token
            database field"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        token = _generate_uuid()
        self._db.update_user(user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """ hashs the password and update the user’s hashed_password field"""

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        pwd = _hash_password(password)
        self._db.update_user(user.id, hashed_password=pwd, reset_token=None)
