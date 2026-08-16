from datetime import datetime, timedelta
from functools import partial
from secrets import token_urlsafe

from django.contrib.auth import get_user_model
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.utils import timezone

from . import settings as jwt_settings_module

User = get_user_model()


class SessionQuerySet(models.QuerySet):
    def active(self):
        """
        Sessions that have not been revoked and have not aged out.

        `expired_at` is null only for sessions created while
        SESSION_EXPIRE_SECONDS was 0, which never age out on their own.
        """
        return self.filter(models.Q(expired_at__isnull=True) | models.Q(expired_at__gt=timezone.now()))


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

    objects = SessionQuerySet.as_manager()

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

    user_agent = models.TextField(
        blank=True,
        default="",
    )

    # Where `ip_address` appeared to be at login, as returned by the
    # configured JWT_GEOLOCATION_PROVIDER. Shaped like types.GeoLocation.
    # Null when no provider is configured or the lookup failed.
    location = models.JSONField(
        null=True,
        blank=True,
        encoder=DjangoJSONEncoder,
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

    # Refresh token rotation state. `refresh_jti` is the only refresh token
    # currently accepted for this session; `previous_refresh_jti` is the one it
    # replaced, honoured for REFRESH_TOKEN_REUSE_GRACE_SECONDS so that a client
    # retrying a dropped response isn't mistaken for an attacker replaying a
    # stolen token. Anything else presented is treated as a compromise.
    refresh_jti = models.CharField(max_length=43, null=True, blank=True)
    previous_refresh_jti = models.CharField(max_length=43, null=True, blank=True)
    rotated_at = models.DateTimeField(null=True, blank=True)

    @property
    def is_expired(self) -> bool:
        return self.expired_at is not None and self.expired_at < timezone.now()

    def rotate_refresh_jti(self) -> str:
        """
        Issue a new refresh token id for this session and return it.

        The outgoing id stays valid for the grace window so that a retried
        refresh doesn't revoke the session.
        """
        jti = token_urlsafe(32)
        self.previous_refresh_jti = self.refresh_jti
        self.refresh_jti = jti
        self.rotated_at = timezone.now()
        self.save(update_fields=["previous_refresh_jti", "refresh_jti", "rotated_at", "updated_at"])
        return jti

    def accepts_refresh_jti(self, jti: str | None) -> bool:
        """
        Whether `jti` is a refresh token id this session will still honour.

        Sessions created before rotation existed have no `refresh_jti`; their
        outstanding refresh tokens carry no `jti` and are adopted once, on
        their next use, rather than logging every user out on upgrade.
        """
        if self.refresh_jti is None:
            return jti is None
        if jti is None:
            return False
        if jti == self.refresh_jti:
            return True
        return jti == self.previous_refresh_jti and self._within_reuse_grace()

    def _within_reuse_grace(self) -> bool:
        grace = jwt_settings_module.jwt_settings.REFRESH_TOKEN_REUSE_GRACE_SECONDS
        rotated_at: datetime | None = self.rotated_at
        if grace <= 0 or rotated_at is None:
            return False
        return timezone.now() - rotated_at <= timedelta(seconds=grace)

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
        return (
            cls.objects.active()
            .filter(user=user)
            .update(
                expired_at=now,
                updated_at=now,
            )
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
    def create_session(
        cls,
        user,
        ip_address: str | None,
        user_agent: str = "",
        location: dict | None = None,
    ) -> "Session":
        """
        Create a new session from a request.

        The session is given a hard expiry of SESSION_EXPIRE_SECONDS so that it
        cannot outlive its own refresh tokens. Set the setting to 0 to opt out
        and keep sessions alive until they are explicitly logged out.
        """
        current_utc = timezone.now()
        max_age = jwt_settings_module.jwt_settings.SESSION_EXPIRE_SECONDS
        return cls.objects.create(
            user=user,
            created_at=current_utc,
            updated_at=current_utc,
            expired_at=current_utc + timedelta(seconds=max_age) if max_age > 0 else None,
            ip_address=ip_address,
            user_agent=user_agent,
            location=location,
        )
