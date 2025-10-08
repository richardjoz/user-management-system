import bcrypt
import jwt
from datetime import datetime, timedelta
import environ

env = environ.Env()
environ.Env.read_env()


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def generate_jwt_token(user_id: int):
    """
    Generates a JWT token for a given user ID.
    """
    expiration = datetime.now() + timedelta(days=1)
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'iat': datetime.now()
        }

    token = jwt.encode(payload, env('SECRET_KEY'), algorithm='HS256')
    return token
