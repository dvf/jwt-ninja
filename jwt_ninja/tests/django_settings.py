SECRET_KEY = "fake-key-long-enough-for-hs256-testing-32b+"  # 44 bytes, avoids InsecureJWTKeyWarning
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "jwt_ninja",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
