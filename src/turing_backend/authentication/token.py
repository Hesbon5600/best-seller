# authors/authentication/token.py
# This file generates token using a username

from datetime import datetime, timedelta
import jwt
from django.conf import settings


def generate_token(email):
    """
    This method generates and return it as a string.
    """
    date = datetime.now() + timedelta(hours=24)

    payload = {
        'username': email,
        'exp': int(date.strftime('%S'))
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    return token.decode('utf-8'), str(timedelta(hours=payload['exp']))