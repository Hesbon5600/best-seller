from .base import *
import os
DEBUG = True

STRIPE_API_KEY = "sk_test_lomdOfxbm7QDgZWvR82UhV6D"

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('DB_NAME', 'turing'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'USER': os.getenv('DB_USER', 'root'),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': '3306',
    }
}


SOCIAL_AUTH_FACEBOOK_KEY = '1413036465538715'
SOCIAL_AUTH_FACEBOOK_SECRET = 'cccc9607c28040969a24406690037e4c'
