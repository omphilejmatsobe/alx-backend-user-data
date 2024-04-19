#!/usr/bin/env python3
"""
Module with class SessionAuth for Session Authentication
"""

import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """
    Class that perfomes Authentication
    """

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates session ID for a user_id
        """

        if user_id is None or not isinstance(user_id, str):
            return None
        _id = str(uuid.uuid4())
        self.user_id_by_session_id[_id] = user_id
        return _id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a User ID based on a Session ID
        """

        if _id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(_id)

    def current_user(self, request=None):
        """Returns a User instance based on a cookie value"""

        _id = self.session_cookie(request)
        if _id is None:
            return None

        user_id = self.user_id_for_session_id(_id)
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Deletes de user session / logout"""

        if request is None:
            return False
        _id = self.session_cookie(request)
        if _id is None:
            return False
        user_id = self.user_id_for_session_id(_id)

        if not user_id:
            return False
        try:
            del self.user_id_by_session_id[_id]
        except Exception:
            pass

        return True
