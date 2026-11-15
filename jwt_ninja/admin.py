from django.contrib import admin
from django.http import HttpRequest

from .models import Session


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "user",
        "created_at",
        "updated_at",
        "expired_at",
        "ip_address",
    ]
    readonly_fields = [
        "id",
        "user",
        "created_at",
        "updated_at",
        "expired_at",
        "rotated_at",
        "ip_address",
        "user_agent",
        "location",
        "data",
    ]
    exclude = [
        "security_stamp",
        "refresh_jti",
        "previous_refresh_jti",
    ]
    list_filter = ["created_at", "expired_at"]
    ordering = ["-id"]
    list_select_related = ["user"]
    show_full_result_count = False

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Session | None = None) -> bool:
        return False
