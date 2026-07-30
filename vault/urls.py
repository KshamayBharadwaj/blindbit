from django.urls import path
from . import views

app_name = 'vault'

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_view, name='upload'),
    path('file/<uuid:file_id>/', views.file_detail, name='file_detail'),
    path('file/<uuid:file_id>/download/', views.download_file, name='download'),
    path('api/files/<uuid:file_id>/download-data/', views.download_file_data, name='download_data'),
    path('file/<uuid:file_id>/delete/', views.delete_file, name='delete'),
    path('api/files/', views.file_list_api, name='file_list_api'),
    path('api/upload/', views.upload_file, name='upload_api'),
]
