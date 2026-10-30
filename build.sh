#!/usr/bin/env bash
# Exit on error
set -o errexit

pip install --upgrade pip
pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate

# Automatically create or update the superuser in Supabase
python manage.py shell -c "
import os
from django.contrib.auth import get_user_model
User = get_user_model()
username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'blindbit')
email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@blindbit.local')
password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'Blindbit@123')
if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f'Superuser {username} created successfully!')
else:
    u = User.objects.get(username=username)
    u.set_password(password)
    u.is_superuser = True
    u.is_staff = True
    u.save()
    print(f'Superuser {username} credentials verified!')
"
