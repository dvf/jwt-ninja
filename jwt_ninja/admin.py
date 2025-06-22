from django.contrib import admin

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
        "ip_address",
        "data",
    ]
    list_filter = ["created_at", "expired_at"]
    ordering = ["-id"]
    list_select_related = ["user"]
    show_full_result_count = False
