"""
WSGI config for backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'turing_backend.settings')
os.environ.setdefault('DJANGO_SETTINGS_MODULE',
                      'turing_backend.settings.development')
application = get_wsgi_application()