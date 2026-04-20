from types import SimpleNamespace

import pytest
from django.http import HttpRequest

from ..authenticators import django_user_authenticator


@pytest.mark.django_db
def test_valid_credentials_returns_user(test_user):
    payload = SimpleNamespace(username="dan", password="dan")
    user = django_user_authenticator(HttpRequest(), payload)
    assert user == test_user


@pytest.mark.django_db
def test_wrong_password_returns_none(test_user):
    payload = SimpleNamespace(username="dan", password="wrong")
    assert django_user_authenticator(HttpRequest(), payload) is None


@pytest.mark.django_db
def test_nonexistent_username_returns_none(test_user):
    payload = SimpleNamespace(username="ghost", password="dan")
    assert django_user_authenticator(HttpRequest(), payload) is None


@pytest.mark.django_db
def test_inactive_user_returns_none(test_user):
    test_user.is_active = False
    test_user.save()

    payload = SimpleNamespace(username="dan", password="dan")
    assert django_user_authenticator(HttpRequest(), payload) is None
