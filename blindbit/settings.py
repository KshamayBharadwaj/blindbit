import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('BLINDBIT_SECRET_KEY')
if not SECRET_KEY:
    import secrets
    SECRET_KEY = f'django-insecure-{secrets.token_hex(32)}'
    print(f'WARNING: Using auto-generated SECRET_KEY. Set BLINDBIT_SECRET_KEY env var for production.')
    print(f'         Generated key: {SECRET_KEY}')

DEBUG = os.environ.get('BLINDBIT_DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.environ.get('BLINDBIT_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

INSTALLED_APPS = [
    'unfold',
    'unfold.contrib.filters',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'blindbit',
    'accounts',
    'vault',
    'sharing',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'blindbit.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates', BASE_DIR],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'blindbit.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/vault/dashboard/'

# Custom user model
AUTH_USER_MODEL = 'accounts.User'

# Email — console backend for development (prints to terminal)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
DEFAULT_FROM_EMAIL = 'noreply@blindbit.local'

# Max upload size: 100MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 104857600
FILE_UPLOAD_MAX_MEMORY_SIZE = 104857600

# WebAuthn
WEBAUTHN_RP_ID = os.environ.get('BLINDBIT_RP_ID', 'localhost')
WEBAUTHN_RP_NAME = os.environ.get('BLINDBIT_RP_NAME', 'BlindBit')
WEBAUTHN_RP_ORIGIN = os.environ.get('BLINDBIT_RP_ORIGIN', 'http://localhost:8000')

# Security settings — enable via BLINDBIT_ENABLE_SSL env var for production
if os.environ.get('BLINDBIT_ENABLE_SSL', 'False').lower() == 'true':
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ──────────────────────────────────────────────
# Unfold Admin
# ──────────────────────────────────────────────
UNFOLD = {
    "SITE_TITLE": "BlindBit Admin",
    "SITE_HEADER": "BlindBit",
    "SITE_SUBHEADER": "zero-knowledge vault",
    "SITE_URL": "/",
    "SITE_SYMBOL": "lock",
    "SHOW_HISTORY": True,
    "SHOW_VIEW_ON_SITE": True,
    "SHOW_BACK_BUTTON": True,
    "SIDEBAR": {
        "show_search": True,
        "show_all_applications": True,
        "navigation": [
            {
                "title": "Content",
                "separator": True,
                "collapsible": True,
                "items": [
                    {"title": "Encrypted Files", "icon": "folder", "link": "/admin/vault/encryptedfile/"},
                ],
            },
            {
                "title": "Sharing",
                "separator": True,
                "collapsible": True,
                "items": [
                    {"title": "File Shares", "icon": "share", "link": "/admin/sharing/fileshare/"},
                ],
            },
            {
                "title": "Users & Auth",
                "separator": True,
                "collapsible": True,
                "items": [
                    {"title": "Users", "icon": "person", "link": "/admin/accounts/user/"},
                    {"title": "Devices", "icon": "devices", "link": "/admin/accounts/device/"},
                    {"title": "Groups", "icon": "group", "link": "/admin/auth/group/"},
                ],
            },
        ],
    },
    "TABS": [
        {
            "models": [
                "accounts.user",
                "accounts.device",
            ],
            "items": [
                {"title": "All Users", "link": "/admin/accounts/user/"},
                {"title": "Devices", "link": "/admin/accounts/device/"},
            ],
        },
    ],
}
