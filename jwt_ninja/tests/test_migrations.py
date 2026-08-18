import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone


@pytest.mark.django_db(transaction=True)
def test_0004_expires_active_pre_stamp_sessions():
    executor = MigrationExecutor(connection)
    executor.migrate([("jwt_ninja", "0003_session_location_session_user_agent")])
    old_apps = executor.loader.project_state([("jwt_ninja", "0003_session_location_session_user_agent")]).apps
    OldSession = old_apps.get_model("jwt_ninja", "Session")

    user = get_user_model().objects.create_user(username="migration-user", password="secret")
    active = OldSession.objects.create(user_id=user.pk)
    already_expired = OldSession.objects.create(user_id=user.pk, expired_at=timezone.now())

    executor = MigrationExecutor(connection)
    executor.migrate([("jwt_ninja", "0004_session_security_stamp")])
    new_apps = executor.loader.project_state([("jwt_ninja", "0004_session_security_stamp")]).apps
    NewSession = new_apps.get_model("jwt_ninja", "Session")

    active_after = NewSession.objects.get(pk=active.pk)
    expired_after = NewSession.objects.get(pk=already_expired.pk)
    assert active_after.expired_at is not None
    assert active_after.expired_at <= timezone.now()
    assert expired_after.expired_at == already_expired.expired_at
