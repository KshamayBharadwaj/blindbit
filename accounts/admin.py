from unfold.admin import ModelAdmin, TabularInline
from unfold.decorators import display, action
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from unfold.contrib.filters.admin import RangeDateTimeFilter
from .models import User, Device

admin.site.unregister(Group)


class DeviceInline(TabularInline):
    model = Device
    fk_name = 'user'
    extra = 0
    fields = ['name', 'prf_enabled', 'last_used', 'created_at']
    readonly_fields = ['id', 'created_at', 'last_used']
    can_delete = True
    show_change_link = True


@admin.register(User)
class UserAdmin(BaseUserAdmin, ModelAdmin):
    list_display = [
        'username', 'email', 'display_is_onboarded', 'display_passphrase',
        'display_device_count', 'date_joined', 'last_login',
    ]
    list_filter = [
        'is_onboarded', 'passphrase_enabled', 'recovery_phrase_confirmed',
        'is_active', 'is_staff', 'is_superuser',
        ('date_joined', RangeDateTimeFilter),
        ('last_login', RangeDateTimeFilter),
    ]
    search_fields = ['username', 'email']
    search_help_text = "Search by username or email address"
    ordering = ['-date_joined']
    date_hierarchy = 'date_joined'
    list_per_page = 20
    list_max_show_all = 100
    preserve_filters = True
    show_full_result_count = True

    fieldsets = [
        ('Account Info', {
            'fields': ['username', 'email', 'password', 'display_name'],
            'classes': ['wide'],
        }),
        ('Onboarding', {
            'fields': ['is_onboarded', 'recovery_phrase_confirmed'],
            'classes': ['wide'],
            'description': 'User setup progress',
        }),
        ('Passphrase', {
            'fields': ['passphrase_enabled', 'passphrase_salt', 'passphrase_verifier'],
            'classes': ['wide', 'collapse'],
            'description': 'Passphrase-based authentication fallback',
        }),
        ('Cryptographic Keys', {
            'fields': [
                'x25519_public_key', 'encrypted_x25519_private_key',
                'wrapped_master_key_prf', 'wrapped_master_key_passphrase',
                'wrapped_master_key_recovery',
            ],
            'classes': ['wide', 'collapse'],
            'description': 'Encrypted key material (read-only)',
        }),
        ('Permissions', {
            'fields': ['is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'],
            'classes': ['wide', 'collapse'],
        }),
        ('Timestamps', {
            'fields': ['last_login', 'date_joined'],
            'classes': ['wide', 'collapse'],
        }),
    ]
    readonly_fields = [
        'x25519_public_key', 'encrypted_x25519_private_key',
        'wrapped_master_key_prf', 'wrapped_master_key_passphrase',
        'wrapped_master_key_recovery',
        'passphrase_salt', 'passphrase_verifier',
        'date_joined', 'last_login',
    ]
    inlines = [DeviceInline]

    @display(description='Onboarded', ordering='is_onboarded')
    def display_is_onboarded(self, obj):
        if obj.is_onboarded:
            return True, 'success'
        return False, ''

    @display(description='Passphrase', ordering='passphrase_enabled')
    def display_passphrase(self, obj):
        if obj.passphrase_enabled:
            return True, 'info'
        return False, ''

    @display(description='Devices', ordering='id')
    def display_device_count(self, obj):
        count = obj.devices.count()
        return count, 'info' if count > 0 else ''

    @action(description='Mark selected users as onboarded')
    def mark_onboarded(self, request, queryset):
        updated = queryset.update(is_onboarded=True)
        self.message_user(request, f'{updated} user(s) marked as onboarded.')

    @action(description='Mark selected users as not onboarded')
    def mark_not_onboarded(self, request, queryset):
        updated = queryset.update(is_onboarded=False)
        self.message_user(request, f'{updated} user(s) marked as not onboarded.')

    actions = [mark_onboarded, mark_not_onboarded]


@admin.register(Device)
class DeviceAdmin(ModelAdmin):
    list_display = [
        'name', 'display_user', 'prf_enabled', 'last_used', 'created_at',
    ]
    list_filter = [
        'prf_enabled',
        ('last_used', RangeDateTimeFilter),
        ('created_at', RangeDateTimeFilter),
    ]
    search_fields = ['name', 'user__username', 'user__email']
    search_help_text = "Search by device name or username"
    ordering = ['-last_used']
    date_hierarchy = 'created_at'
    list_per_page = 25
    list_select_related = ['user']
    raw_id_fields = ['user']

    fieldsets = [
        ('Device Info', {
            'fields': ['name', 'credential_id', 'public_key'],
            'classes': ['wide'],
        }),
        ('Owner', {
            'fields': ['user'],
            'classes': ['wide'],
        }),
        ('Settings', {
            'fields': ['prf_enabled', 'wrapped_master_key'],
            'classes': ['wide'],
        }),
        ('Activity', {
            'fields': ['last_used', 'created_at'],
            'classes': ['wide'],
        }),
    ]
    readonly_fields = ['credential_id', 'public_key', 'wrapped_master_key', 'created_at', 'last_used']

    @display(description='User', ordering='user__username')
    def display_user(self, obj):
        return obj.user.username


@admin.register(Group)
class GroupAdmin(ModelAdmin):
    list_display = ['name', 'display_user_count']
    search_fields = ['name']
    search_help_text = "Search by group name"
    list_per_page = 20
    filter_horizontal = ['permissions']

    @display(description='Users')
    def display_user_count(self, obj):
        count = obj.user_set.count()
        return count, ''

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'permissions' in form.base_fields:
            form.base_fields['permissions'].widget.attrs['style'] = 'height: 300px;'
        return form
