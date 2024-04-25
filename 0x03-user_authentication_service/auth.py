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
