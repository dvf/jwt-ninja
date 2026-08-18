import os

SECRET_KEY = "django-secret-is-not-used-for-jwt-signing"
JWT_SECRET_KEY = "fake-dedicated-jwt-key-long-enough-for-hs256"
JWT_ISSUER = "https://issuer.example.test"
JWT_AUDIENCE = "jwt-ninja-tests"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "jwt_ninja",
]

if os.environ.get("JWT_NINJA_TEST_POSTGRES") == "1":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("POSTGRES_DB", "jwtninja"),
            "USER": os.environ.get("POSTGRES_USER", "postgres"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "postgres"),
            "HOST": os.environ.get("POSTGRES_HOST", "127.0.0.1"),
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
            "OPTIONS": {"timeout": 10},
        }
    }
