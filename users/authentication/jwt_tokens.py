import jwt
from datetime import datetime
from django.conf import settings
from rest_framework import authentication, exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from sqlalchemy.exc import SQLAlchemyError
from User_Management.dbsession import Session
from users.models import UserToken, UserLogin
import environ

env = environ.Env()
environ.Env.read_env()


class UserTokenAuthentication(BaseAuthentication):
    """
    Custom JWT Authentication for user login using SQLAlchemy.
    """

    def authenticate(self, request):
        session = Session()

        # Extract and validate Authorization header
        auth_header = get_authorization_header(request).split()
        if not auth_header or auth_header[0].lower() != b'bearer':
            return None

        if len(auth_header) != 2:
            raise exceptions.AuthenticationFailed("Invalid token header format")

        try:
            token = auth_header[1].decode("utf-8")
        except UnicodeDecodeError:
            raise exceptions.AuthenticationFailed("Token contains invalid characters")

        if token.lower() == "null":
            raise exceptions.AuthenticationFailed("Null token is not allowed")

        # Decode the JWT token
        try:
            payload = jwt.decode(token, env('SECRET_KEY'), algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token has expired")
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed("Token decode failed. Possibly malformed or tampered.")
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed("Invalid token")

        auth_id = payload.get("auth_id")
        expiry = payload.get("exp")

        if not auth_id or not expiry:
            raise exceptions.AuthenticationFailed("Invalid token payload")

        try:
            # Check if token exists in DB
            token_record = session.query(UserToken).filter_by(auth_id=auth_id, token=token).first()
            if not token_record:
                raise exceptions.AuthenticationFailed("Token not found or revoked")

            # Check expiry
            if datetime.now() > token_record.exp:
                raise exceptions.AuthenticationFailed("Token has expired")

            # Get the user
            user = session.query(UserLogin).filter_by(id=auth_id).first()
            if not user:
                raise exceptions.AuthenticationFailed("User not found")

        except SQLAlchemyError:
            raise exceptions.AuthenticationFailed("Database error during authentication")
        finally:
            session.close()

        return (user, token)

    def authenticate_header(self, request):
        return "Bearer"
