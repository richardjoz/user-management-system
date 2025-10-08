from django.contrib.auth.backends import BaseBackend
from sqlalchemy.exc import SQLAlchemyError
from User_Management.dbsession import Session
from users.models import UserLogin
from users.utils import verify_password


class SQLAlchemyUserBackend(BaseBackend):
    """
    Custom SQLAlchemy authentication backend for app users
    """
    def authenticate(self, request, username=None, password=None):
        if not username or not password:
            return None

        session = Session()
        try:
            user = session.query(UserLogin).filter_by(username=username).first()
            if user and verify_password(password, user.password_hash):
                return user
        except SQLAlchemyError as e:
            print("[User Auth] DB Error:", e)
        finally:
            session.close()
        return None

    def get_user(self, user_id):
        session = Session()
        try:
            return session.query(UserLogin).filter_by(id=user_id).first()
        except SQLAlchemyError:
            return None
        finally:
            session.close()
