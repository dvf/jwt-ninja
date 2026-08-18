import hashlib
import hmac
import logging
import time
from datetime import timedelta
from functools import partial
from secrets import randbelow, token_urlsafe

from django.contrib.auth import get_user_model
from django.core.serializers.json import DjangoJSONEncoder
from django.db import OperationalError, connection, models, transaction
from django.utils import timezone

from . import settings as jwt_settings_module

User = get_user_model()
logger = logging.getLogger(__name__)


class SecurityStampChangedError(Exception):
    """The authenticated user snapshot no longer matches durable credentials."""


def security_stamp_for_user(user) -> str:
    """Return a fixed-size, non-reversible fingerprint of the user's auth hash."""
    auth_hash = user.get_session_auth_hash()
    if not isinstance(auth_hash, str) or not auth_hash:
        raise ValueError("User returned an invalid session authentication hash")
    key = jwt_settings_module.jwt_settings.SECRET_KEY.encode("utf-8")
    return hmac.new(key, auth_hash.encode("utf-8"), hashlib.sha256).hexdigest()


class SessionQuerySet(models.QuerySet):
    def active(self):
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

    id = models.CharField(primary_key=True, max_length=43, default=partial(token_urlsafe, 32))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expired_at = models.DateTimeField(null=True, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, default="")
    location = models.JSONField(null=True, blank=True, encoder=DjangoJSONEncoder)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="jwt_sessions")
    data = models.JSONField(default=dict, encoder=DjangoJSONEncoder)

    # Migration 0004 expires pre-stamp sessions. NULL still fails closed if a
    # row is inserted manually or restored from an old backup.
    security_stamp = models.CharField(max_length=64, null=True, blank=True)

    refresh_jti = models.CharField(max_length=43, null=True, blank=True)
    # Retained for migration/schema compatibility only; neither is authorized.
    previous_refresh_jti = models.CharField(max_length=43, null=True, blank=True)
    rotated_at = models.DateTimeField(null=True, blank=True)

    @property
    def is_expired(self) -> bool:
        return self.expired_at is not None and self.expired_at <= timezone.now()

    def invalidate_session(self):
        self.expired_at = timezone.now()
        self.save(update_fields=["expired_at", "updated_at"])

    def security_stamp_matches(self, user) -> bool:
        """Constant-time stamp validation; failures revoke this session."""
        try:
            expected = security_stamp_for_user(user)
            matches = self.security_stamp is not None and hmac.compare_digest(str(self.security_stamp), expected)
        except Exception as exc:
            # Preserve fail-closed behavior without logging credentials, hashes,
            # users, or exception text (which may contain backend data).
            logger.warning("Session security-stamp evaluation failed (%s)", type(exc).__name__)
            matches = False
        if not matches:
            now = timezone.now()
            type(self).objects.filter(pk=self.pk).update(expired_at=now, updated_at=now)
            self.expired_at = now
        return matches

    def initialize_refresh_jti(self, jti: str | None = None) -> str:
        """Initialize rotation state for a newly authenticated session only."""
        if self.refresh_jti is not None:
            raise ValueError("Refresh JTI is already initialized")
        jti = jti or token_urlsafe(32)
        if len(jti) > 43:
            raise ValueError("Refresh JTI is too long")
        self.refresh_jti = jti
        self.save(update_fields=["refresh_jti", "updated_at"])
        return jti

    @classmethod
    def consume_refresh_jti(
        cls,
        *,
        session_id: str,
        user_id,
        presented_jti: str,
        replacement_jti: str,
        expected_security_stamp: str,
    ) -> tuple[str, str | None]:
        """Atomically consume the live JTI in favor of a pre-minted candidate.

        The replacement is supplied by the caller so token construction can
        succeed before durable rotation state changes. A stale/replayed token
        revokes the family in the same transaction.
        """
        if not replacement_jti or len(replacement_jti) > 43:
            raise ValueError("Replacement refresh JTI is invalid")
        now = timezone.now()
        with transaction.atomic():  # pyrefly: ignore [bad-context-manager]
            updated = cls.objects.filter(
                models.Q(expired_at__isnull=True) | models.Q(expired_at__gt=now),
                pk=session_id,
                user_id=user_id,
                refresh_jti=presented_jti,
                security_stamp=expected_security_stamp,
            ).update(
                refresh_jti=replacement_jti,
                updated_at=now,
            )
            if updated == 1:
                return "consumed", replacement_jti

            try:
                current = cls.objects.select_for_update().get(pk=session_id)
            except cls.DoesNotExist:
                return "missing", None
            if current.user_id != user_id:
                return "wrong_user", None
            if current.expired_at is not None and current.expired_at <= now:
                return "expired", None
            if current.security_stamp != expected_security_stamp:
                current.expired_at = now
                current.save(update_fields=["expired_at", "updated_at"])
                return "security_changed", None
            # The only remaining failed predicate is the exact current JTI: a
            # concurrent consume or replay. Revoke before leaving the block.
            current.expired_at = now
            current.save(update_fields=["expired_at", "updated_at"])
            return "reused", None

    @classmethod
    def invalidate_all_user_sessions(cls, user):
        now = timezone.now()
        return cls.objects.active().filter(user=user).update(expired_at=now, updated_at=now)

    @classmethod
    def purge_expired_sessions(cls):
        return cls.objects.filter(expired_at__lte=timezone.now()).delete()

    @classmethod
    def create_session(
        cls,
        user,
        ip_address: str | None,
        user_agent: str = "",
        location: dict | None = None,
        *,
        expected_security_stamp: str | None = None,
    ) -> "Session":
        """Create a stamped session while atomically enforcing the user cap.

        SQLite has no row-level ``SELECT FOR UPDATE``. Its transient lock
        errors are retried around the complete cap/create transaction; all
        other database errors and backends fail immediately.
        """
        config = jwt_settings_module.jwt_settings
        authenticated_stamp = expected_security_stamp or security_stamp_for_user(user)
        attempts = 8 if connection.vendor == "sqlite" else 1

        for attempt in range(attempts):
            try:
                now = timezone.now()
                with transaction.atomic():  # pyrefly: ignore [bad-context-manager]
                    locked_user = User.objects.select_for_update().get(pk=user.pk)
                    current_stamp = security_stamp_for_user(locked_user)
                    if not hmac.compare_digest(current_stamp, authenticated_stamp):
                        raise SecurityStampChangedError
                    active = cls.objects.active().filter(user=locked_user).order_by("created_at", "id")
                    excess = active.count() - config.MAX_ACTIVE_SESSIONS + 1
                    if excess > 0:
                        oldest_ids = list(active.values_list("id", flat=True)[:excess])
                        cls.objects.filter(id__in=oldest_ids).update(expired_at=now, updated_at=now)
                    max_age = config.SESSION_EXPIRE_SECONDS
                    return cls.objects.create(
                        user=locked_user,
                        expired_at=now + timedelta(seconds=max_age) if max_age > 0 else None,
                        ip_address=ip_address,
                        user_agent=(user_agent or "")[:512],
                        location=location,
                        security_stamp=current_stamp,
                    )
            except OperationalError as exc:
                is_sqlite_lock = connection.vendor == "sqlite" and "locked" in str(exc).lower()
                if not is_sqlite_lock or attempt == attempts - 1:
                    raise
                time.sleep(0.01 * (2**attempt) + randbelow(10) / 1000)

        raise RuntimeError("unreachable")
