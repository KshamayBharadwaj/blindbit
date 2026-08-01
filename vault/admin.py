from unfold.admin import ModelAdmin
from unfold.decorators import display, action
from django.contrib import admin
from .models import EncryptedFile, UploadSession, FileChunk


@admin.register(EncryptedFile)
class EncryptedFileAdmin(ModelAdmin):
    list_display = [
        'display_short_id', 'display_owner', 'mime_type',
        'display_size', 'uploaded_at',
    ]
    list_filter = [
        'mime_type',
        'uploaded_at',
    ]
    search_fields = ['owner__username', 'owner__email', 'mime_type']
    search_help_text = "Search by owner username or MIME type"
    ordering = ['-uploaded_at']
    date_hierarchy = 'uploaded_at'
    list_per_page = 25
    list_select_related = ['owner']
    raw_id_fields = ['owner']

    fieldsets = [
        ('File Info', {
            'fields': ['original_size', 'mime_type', 'encrypted_filename'],
            'classes': ['wide'],
        }),
        ('Owner', {
            'fields': ['owner'],
            'classes': ['wide'],
        }),
        ('Cryptographic Material', {
            'fields': ['ciphertext', 'wrapped_file_key', 'nonce', 'auth_tag'],
            'classes': ['wide', 'collapse'],
            'description': 'Encrypted payload — data is not readable in plaintext',
        }),
        ('Metadata', {
            'fields': ['encrypted_metadata'],
            'classes': ['wide', 'collapse'],
        }),
        ('Timestamps', {
            'fields': ['uploaded_at', 'updated_at'],
            'classes': ['wide', 'collapse'],
        }),
    ]
    readonly_fields = ['ciphertext', 'wrapped_file_key', 'nonce', 'auth_tag',
                       'encrypted_filename', 'encrypted_metadata',
                       'uploaded_at', 'updated_at']

    @display(description='ID', ordering='id')
    def display_short_id(self, obj):
        return str(obj.id)[:8]

    @display(description='Owner', ordering='owner__username')
    def display_owner(self, obj):
        return obj.owner.username

    @display(description='Size')
    def display_size(self, obj):
        if obj.original_size < 1024:
            return f'{obj.original_size} B'
        elif obj.original_size < 1024 ** 2:
            return f'{obj.original_size / 1024:.1f} KB'
        else:
            return f'{obj.original_size / 1024 ** 2:.1f} MB'

    @action(description='Purge selected files permanently')
    def purge_files(self, request, queryset):
        count = queryset.count()
        queryset.delete()
        self.message_user(request, f'{count} encrypted file(s) purged.')

    actions = [purge_files]

    def get_actions(self, request):
        actions = super().get_actions(request)
        if not request.user.is_superuser:
            if 'purge_files' in actions:
                del actions['purge_files']
        return actions


@admin.register(UploadSession)
class UploadSessionAdmin(ModelAdmin):
    list_display = ['display_short_id', 'display_owner', 'original_size', 'chunks_received', 'total_chunks', 'created_at', 'expires_at']
    list_filter = ['created_at', 'expires_at']
    search_fields = ['owner__username', 'owner__email']
    readonly_fields = ['token', 'encrypted_filename', 'wrapped_file_key', 'nonce',
                       'mime_type', 'original_size', 'chunk_size', 'total_chunks',
                       'chunks_received', 'created_at', 'expires_at']
    ordering = ['-created_at']

    @display(description='ID', ordering='id')
    def display_short_id(self, obj):
        return str(obj.id)[:8]

    @display(description='Owner', ordering='owner__username')
    def display_owner(self, obj):
        return obj.owner.username


@admin.register(FileChunk)
class FileChunkAdmin(ModelAdmin):
    list_display = ['display_short_id', 'session', 'index', 'display_size']
    list_filter = ['session']
    ordering = ['session', 'index']
    readonly_fields = ['session', 'index', 'ciphertext', 'nonce', 'auth_tag']

    @display(description='ID', ordering='id')
    def display_short_id(self, obj):
        return str(obj.id)[:8]

    @display(description='Bytes')
    def display_size(self, obj):
        return f'{len(obj.ciphertext)} B'
