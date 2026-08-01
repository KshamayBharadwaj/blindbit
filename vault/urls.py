from django.urls import path
from . import views

app_name = 'vault'

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_view, name='upload'),
    path('file/<uuid:file_id>/', views.file_detail, name='file_detail'),
    path('file/<uuid:file_id>/download/', views.download_file, name='download'),
    path('api/files/<uuid:file_id>/download-data/', views.download_file_data, name='download_data'),
    path('api/files/<uuid:file_id>/rewrap-key/', views.rewrap_file_key, name='rewrap_key'),
    path('api/files/<uuid:file_id>/favorite/', views.toggle_favorite, name='toggle_favorite'),
    path('api/files/bulk-favorite/', views.bulk_favorite, name='bulk_favorite'),
    path('api/files/bulk-move/', views.bulk_move, name='bulk_move'),
    path('api/files/bulk-delete/', views.bulk_delete, name='bulk_delete'),
    path('file/<uuid:file_id>/delete/', views.delete_file, name='delete'),
    path('trash/', views.trash_view, name='trash'),
    path('file/<uuid:file_id>/restore/', views.restore_file, name='restore_file'),
    path('file/<uuid:file_id>/purge/', views.purge_file, name='purge_file'),
    path('api/trash/empty/', views.empty_trash, name='empty_trash'),
    path('file/<uuid:file_id>/move/', views.move_file, name='move_file'),
    path('api/files/', views.file_list_api, name='file_list_api'),
    path('api/upload/', views.upload_file, name='upload_api'),
    path('api/folders/create/', views.create_folder, name='create_folder'),
    path('api/folders/<uuid:folder_id>/rename/', views.rename_folder, name='rename_folder'),
    path('api/folders/<uuid:folder_id>/delete/', views.delete_folder, name='delete_folder'),
    path('folder/<uuid:folder_id>/', views.dashboard, name='folder_view'),
]
