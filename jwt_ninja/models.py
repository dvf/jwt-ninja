from functools import cached_property, partial
from secrets import token_urlsafe

from django.contrib.auth import get_user_model
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.utils import timezone

User = get_user_model()


class Session(models.Model):
    class Meta:
        verbose_name = "JWT Session"
        verbose_name_plural = "JWT Sessions"

        indexes = [
            models.Index(
                fields=["expired_at"],
                name="idx_non_null_expired_at",
                condition=models.Q(expired_at__isnull=False),
            ),
            models.Index(fields=["user"]),
        ]

    id = models.CharField(
        primary_key=True,
        max_length=43,  # token_urlsafe(32) is 43 chars
        default=partial(token_urlsafe, 32),
    )

    # Dates
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expired_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
    )

    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="jwt_sessions",
    )

    data = models.JSONField(
        default=dict,
        encoder=DjangoJSONEncoder,
    )

    @cached_property
    def is_expired(self):
        return self.expired_at and self.expired_at < timezone.now()

    def invalidate_session(self):
        """
        Explicitly invalidate a session.
        """
        self.expired_at = timezone.now()
        self.save()

    @classmethod
    def invalidate_all_user_sessions(cls, user):
        """
        Invalidate all sessions for a user.
        """
        now = timezone.now()
        return cls.objects.filter(
            user=user,
            expired_at__isnull=True,
        ).update(
            expired_at=now,
            updated_at=now,
        )

    @classmethod
    def purge_expired_sessions(cls):
        """
        Delete sessions that have expired.
        """
        return cls.objects.filter(
            expired_at__lt=timezone.now(),
        ).delete()

    @classmethod
    def create_session(cls, user, ip_address: str) -> "Session":
        """
        Create a new session from a request.
        """
        current_utc = timezone.now()
        return cls.objects.create(
            user=user,
            created_at=current_utc,
            updated_at=current_utc,
            ip_address=ip_address,
        )
