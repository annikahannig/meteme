from django.contrib import admin
from sessionlock import models

class LockAdmin(admin.ModelAdmin):
    list_display = [
        'user',
        'session_active',
        'client_identifier',
        'client_ip',
        'user_agent',
    ]

    list_display_links = ['user']

    readonly_fields = [
        'user',
        'client_ip',
        'user_agent',
        'client_identifier',
    ]


admin.site.register(models.Lock, LockAdmin)


