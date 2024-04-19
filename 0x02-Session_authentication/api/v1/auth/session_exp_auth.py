#!/usr/bin/env python3
"""
Module with class SessionExpAuth for Expiration of Session Authentication
"""

from api.v1.auth.session_auth import SessionAuth
from datetime import datetime, timedelta
from models.user import User
from os import getenv


class SessionExpAuth(SessionAuth):
    """Session Expiration Class"""

    def __init__(self):
        """Constructor Method"""
        DURATION = getenv('SESSION_DURATION')
        try:
            duration = int(DURATION)
        except Exception:
            duration = 0
        self.duration = duration

    def create_session(self, user_id=None):
        """Creation session with expiration"""
        _id = super().create_session(user_id)
        if _id is None:
            return None
        session_dictionary = {
            "user_id": user_id,
            "created_at": datetime.now()
        }

        self.user_id_by_session_id[_id] = session_dictionary
        return _id

    def user_id_for_session_id(self, session_id=None):
        """gets user_id from session_id"""

        if _id is None:
            return None
        if _id not in self.user_id_by_session_id.keys():
            return None
        session_dictionary = self.user_id_by_session_id.get(_id)
        if session_dictionary is None:
            return None
        if self.duration <= 0:
            return session_dictionary.get('user_id')
        created_at = session_dictionary.get('created_at')

        if created_at is None:
            return None

        expired_time = created_at + timedelta(seconds=self.duration)
        if expired_time < datetime.now():
            return None

        return session_dictionary.get('user_id')
