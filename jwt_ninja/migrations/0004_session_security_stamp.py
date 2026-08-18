from django.db import migrations, models
from django.db.models import Q
from django.utils import timezone


def expire_pre_stamp_sessions(apps, schema_editor):
    """Force logout for every session active when security stamps arrive."""
    Session = apps.get_model("jwt_ninja", "Session")
    now = timezone.now()
    Session.objects.filter(Q(expired_at__isnull=True) | Q(expired_at__gt=now)).update(expired_at=now)


class Migration(migrations.Migration):
    dependencies = [("jwt_ninja", "0003_session_location_session_user_agent")]

    operations = [
        migrations.AddField(
            model_name="session",
            name="security_stamp",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.RunPython(expire_pre_stamp_sessions, migrations.RunPython.noop),
    ]
