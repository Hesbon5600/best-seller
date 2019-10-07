release: python manage.py migrate
web: gunicorn turing_backend.wsgi:application --env DJANGO_SETTINGS_MODULE='turing_backend.settings.development'
