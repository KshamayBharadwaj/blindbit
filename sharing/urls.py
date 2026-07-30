from django.urls import path
from . import views

app_name = 'sharing'

urlpatterns = [
    path('shared-with-me/', views.shared_with_me, name='shared_with_me'),
    path('file/<uuid:file_id>/', views.share_view, name='share_view'),
    path('api/create/', views.create_share, name='create_share'),
    path('api/revoke/<uuid:share_id>/', views.revoke_share, name='revoke_share'),
    path('api/re-encrypt/', views.re_encrypt_and_reshare, name='re_encrypt'),
    path('api/lookup-user/', views.lookup_user, name='lookup_user'),
    path('api/shared-files/', views.shared_files_api, name='shared_files_api'),
]
