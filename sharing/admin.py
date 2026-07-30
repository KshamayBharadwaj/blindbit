from unfold.admin import ModelAdmin
from unfold.decorators import display, action
from django.contrib import admin
from .models import FileShare


@admin.register(FileShare)
class FileShareAdmin(ModelAdmin):
    list_display = [
        'display_short_id', 'display_file_id', 'display_owner',
        'display_recipient', 'display_revoked', 'created_at',
    ]
    list_filter = [
        'revoked',
        'created_at',
    ]
    search_fields = [
        'owner__username', 'owner__email',
        'recipient__username', 'recipient__email',
    ]
    search_help_text = "Search by owner or recipient username"
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    list_per_page = 25
    list_select_related = ['owner', 'recipient', 'file']
    raw_id_fields = ['owner', 'recipient', 'file']

    fieldsets = [
        ('Share Details', {
            'fields': ['file', 'owner', 'recipient', 'revoked'],
            'classes': ['wide'],
        }),
        ('Cryptographic Material', {
            'fields': ['wrapped_file_key', 'ephemeral_public_key', 'nonce'],
            'classes': ['wide', 'collapse'],
            'description': 'ECDH-wrapped key material — read-only',
        }),
        ('Timestamps', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['wide', 'collapse'],
        }),
    ]
    readonly_fields = ['wrapped_file_key', 'ephemeral_public_key', 'nonce',
                       'created_at', 'updated_at']

    @display(description='ID', ordering='id')
    def display_short_id(self, obj):
        return str(obj.id)[:8]

    @display(description='File', ordering='file__id')
    def display_file_id(self, obj):
        return str(obj.file.id)[:8]

    @display(description='Owner', ordering='owner__username')
    def display_owner(self, obj):
        return obj.owner.username

    @display(description='Recipient', ordering='recipient__username')
    def display_recipient(self, obj):
        return obj.recipient.username

    @display(description='Status', ordering='revoked')
    def display_revoked(self, obj):
        if obj.revoked:
            return False, 'danger'
        return True, 'success'

    @action(description='Revoke selected shares')
    def revoke_shares(self, request, queryset):
        updated = queryset.update(revoked=True)
        self.message_user(request, f'{updated} share(s) revoked.')

    @action(description='Restore selected shares')
    def restore_shares(self, request, queryset):
        updated = queryset.update(revoked=False)
        self.message_user(request, f'{updated} share(s) restored.')

    actions = [revoke_shares, restore_shares]
