#!/bin/sh
python manage.py collectstatic
python manage.py migrate
uwsgi --ini uwsgi.ini