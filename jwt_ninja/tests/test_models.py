from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from ..models import Session

User = get_user_model()


@pytest.mark.django_db
def test_create_session_with_ip_address(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")

    assert session.user == test_user
    assert session.ip_address == "1.2.3.4"
    # Sessions get a hard expiry from SESSION_EXPIRE_SECONDS
    assert session.expired_at is not None
    assert session.expired_at > timezone.now()


@pytest.mark.django_db
def test_create_session_with_none_ip_address(test_user):
    session = Session.create_session(user=test_user, ip_address=None)

    assert session.user == test_user
    assert session.ip_address is None


@pytest.mark.django_db
def test_is_expired_is_false_when_expired_at_is_none(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")

    assert session.is_expired is False


@pytest.mark.django_db
def test_is_expired_is_true_when_expired_at_is_in_the_past(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")
    session.expired_at = timezone.now() - timedelta(seconds=1)
    session.save()

    assert session.is_expired is True


@pytest.mark.django_db
def test_is_expired_is_false_when_expired_at_is_in_the_future(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")
    session.expired_at = timezone.now() + timedelta(hours=1)
    session.save()

    assert session.is_expired is False


@pytest.mark.django_db
def test_is_expired_reflects_updates(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")

    assert session.is_expired is False

    session.expired_at = timezone.now() - timedelta(seconds=1)
    session.save()

    assert session.is_expired is True


@pytest.mark.django_db
def test_invalidate_session_sets_expired_at(test_user):
    session = Session.create_session(user=test_user, ip_address="1.2.3.4")
    assert session.is_expired is False

    before = timezone.now()
    session.invalidate_session()
    after = timezone.now()

    session.refresh_from_db()
    assert session.expired_at is not None
    assert before <= session.expired_at <= after


@pytest.mark.django_db
def test_invalidate_all_user_sessions(test_user):
    other_user = User.objects.create_user(
        email="other@example.com",
        username="other",
        password="other",
    )

    session_a = Session.create_session(user=test_user, ip_address="1.2.3.4")
    session_b = Session.create_session(user=test_user, ip_address="1.2.3.5")
    other_session = Session.create_session(user=other_user, ip_address="1.2.3.6")

    count = Session.invalidate_all_user_sessions(test_user)

    assert count == 2

    session_a.refresh_from_db()
    session_b.refresh_from_db()
    other_session.refresh_from_db()

    assert session_a.is_expired is True
    assert session_b.is_expired is True
    assert other_session.is_expired is False


@pytest.mark.django_db
def test_purge_expired_sessions(test_user):
    active = Session.create_session(user=test_user, ip_address="1.2.3.4")

    expired_session = Session.create_session(user=test_user, ip_address="1.2.3.5")
    expired_session.expired_at = timezone.now() - timedelta(seconds=1)
    expired_session.save()

    count, per_model = Session.purge_expired_sessions()

    assert count == 1
    assert per_model == {Session._meta.label: 1}

    assert Session.objects.filter(pk=active.pk).exists()
    assert not Session.objects.filter(pk=expired_session.pk).exists()
