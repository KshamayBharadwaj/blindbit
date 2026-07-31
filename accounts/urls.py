from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('recovery/', views.recovery_view, name='recovery'),
    path('devices/', views.devices_view, name='devices'),
    path('api/registration-options/', views.registration_options, name='registration_options'),
    path('api/register-begin/', views.register_complete, name='register_begin'),
    path('api/login-begin/', views.login_begin, name='login_begin'),
    path('api/login-complete/', views.login_complete, name='login_complete'),
    path('api/login-passphrase/', views.login_passphrase, name='login_passphrase'),
    path('api/login-send-otp/', views.login_send_otp, name='login_send_otp'),
    path('api/confirm-recovery/', views.confirm_recovery, name='confirm_recovery'),
    path('api/my-keys/', views.my_keys, name='my_keys'),
    path('api/keys-setup/', views.keys_setup, name='keys_setup'),
    path('api/device/add-options/', views.add_device_options, name='add_device_options'),
    path('api/device/add-complete/', views.add_device_complete, name='add_device_complete'),
    path('api/device/<uuid:device_id>/send-otp/', views.send_remove_otp, name='send_remove_otp'),
    path('api/device/<uuid:device_id>/verify-remove/', views.verify_remove_device, name='verify_remove_device'),
]
