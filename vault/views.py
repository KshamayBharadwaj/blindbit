import json
import base64
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from .models import EncryptedFile, VaultFolder
from sharing.models import FileShare

@login_required
def dashboard(request, folder_id=None):
    folders = VaultFolder.objects.filter(owner=request.user).order_by('-is_favorites', 'name')

    current_folder = None
    if folder_id:
        current_folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)

    my_files = EncryptedFile.objects.filter(owner=request.user)
    if current_folder:
        if current_folder.is_favorites:
            # Smart folder: shows every starred file regardless of its location
            my_files = EncryptedFile.objects.filter(owner=request.user, is_favorite=True)
        else:
            my_files = my_files.filter(folder=current_folder)
    # else: root shows every file; the Location column identifies its folder

    shared_with_me = FileShare.objects.filter(recipient=request.user, revoked=False)

    # Recent = own + shared files, newest by last open (falling back to upload time)
    recent = []
    seen = set()
    for f in EncryptedFile.objects.filter(owner=request.user).select_related('folder'):
        if f.id in seen:
            continue
        seen.add(f.id)
        recent.append((f.last_opened_at or f.uploaded_at, f, False, None))
    for s in shared_with_me.select_related('file'):
        if s.file_id in seen:
            continue
        seen.add(s.file_id)
        recent.append((s.file.last_opened_at or s.file.uploaded_at, s.file, True, s))
    recent.sort(key=lambda x: x[0], reverse=True)
    recent_items = recent[:8]

    return render(request, 'vault/dashboard.html', {
        'files': my_files,
        'shared_files': shared_with_me,
        'folders': folders,
        'current_folder': current_folder,
        'recent_items': recent_items,
        'favorites_count': EncryptedFile.objects.filter(owner=request.user, is_favorite=True).count(),
    })

@login_required
def upload_view(request):
    folder_id = request.GET.get('folder')
    current_folder = None
    if folder_id:
        current_folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)
        if current_folder.is_favorites:
            return redirect('vault:dashboard')
    return render(request, 'vault/upload.html', {
        'current_folder': current_folder,
        'folders': VaultFolder.objects.filter(owner=request.user),
    })

@login_required
@require_POST
def create_folder(request):
    name = (request.POST.get('name') or '').strip()[:255]
    if not name:
        return JsonResponse({'error': 'Folder name is required'}, status=400)
    folder = VaultFolder.objects.create(owner=request.user, name=name)
    return JsonResponse({'status': 'ok', 'folder_id': str(folder.id)})

@login_required
@require_POST
def delete_folder(request, folder_id):
    folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)
    if folder.is_favorites:
        return JsonResponse({'error': 'The Favorites folder cannot be deleted'}, status=400)
    folder.delete()
    return JsonResponse({'status': 'ok'})

@login_required
@require_POST
def rename_folder(request, folder_id):
    folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)
    if folder.is_favorites:
        return JsonResponse({'error': 'The Favorites folder cannot be renamed'}, status=400)
    name = (request.POST.get('name') or '').strip()[:255]
    if not name:
        return JsonResponse({'error': 'Folder name is required'}, status=400)
    folder.name = name
    folder.save(update_fields=['name'])
    return JsonResponse({'status': 'ok'})

@login_required
@require_POST
def move_file(request, file_id):
    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    folder_id = request.POST.get('folder_id')
    if folder_id:
        folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)
        if folder.is_favorites:
            return JsonResponse({'error': 'Starred files stay where they are — use the star button instead'}, status=400)
        file.folder = folder
    else:
        file.folder = None
    file.save(update_fields=['folder', 'updated_at'])
    return JsonResponse({'status': 'ok'})

@login_required
@require_POST
def toggle_favorite(request, file_id):
    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    file.is_favorite = not file.is_favorite
    file.save(update_fields=['is_favorite'])
    if file.is_favorite:
        # Auto-create the Favorites smart folder the first time a file is starred
        VaultFolder.objects.get_or_create(owner=request.user, is_favorites=True, defaults={'name': 'Favorites'})
    return JsonResponse({'status': 'ok', 'is_favorite': file.is_favorite})

@login_required
@require_POST
def bulk_favorite(request):
    ids = request.POST.getlist('file_ids')
    if not ids:
        return JsonResponse({'error': 'No files selected'}, status=400)
    files = EncryptedFile.objects.filter(owner=request.user, id__in=ids)
    value = request.POST.get('is_favorite') == '1'
    files.update(is_favorite=value)
    if value:
        VaultFolder.objects.get_or_create(owner=request.user, is_favorites=True, defaults={'name': 'Favorites'})
    return JsonResponse({'status': 'ok', 'count': files.count()})

@login_required
@require_POST
def bulk_move(request):
    ids = request.POST.getlist('file_ids')
    if not ids:
        return JsonResponse({'error': 'No files selected'}, status=400)
    folder_id = request.POST.get('folder_id')
    folder = None
    if folder_id:
        folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)
        if folder.is_favorites:
            return JsonResponse({'error': 'Starred files stay where they are — use the star button instead'}, status=400)
    EncryptedFile.objects.filter(owner=request.user, id__in=ids).update(folder=folder)
    return JsonResponse({'status': 'ok', 'count': len(ids)})

@login_required
@require_POST
def bulk_delete(request):
    ids = request.POST.getlist('file_ids')
    if not ids:
        return JsonResponse({'error': 'No files selected'}, status=400)
    qs = EncryptedFile.objects.filter(owner=request.user, id__in=ids)
    count = qs.count()
    qs.delete()
    return JsonResponse({'status': 'ok', 'count': count})

@login_required
@require_POST
def upload_file(request):
    ciphertext = request.FILES.get('ciphertext')
    if not ciphertext:
        return JsonResponse({'error': 'No ciphertext provided'}, status=400)

    if ciphertext.size > 104857600:
        return JsonResponse({'error': 'File exceeds 100MB limit'}, status=400)

    folder = None
    folder_id = request.POST.get('folder_id')
    if folder_id:
        folder = get_object_or_404(VaultFolder, id=folder_id, owner=request.user)
        if folder.is_favorites:
            return JsonResponse({'error': 'You cannot upload directly into Favorites — star a file instead'}, status=400)

    encrypted_file = EncryptedFile.objects.create(
        owner=request.user,
        folder=folder,
        ciphertext=ciphertext.read(),
        wrapped_file_key=request.POST.get('wrapped_file_key', ''),
        encrypted_filename=request.POST.get('encrypted_filename', ''),
        encrypted_metadata=request.POST.get('encrypted_metadata', ''),
        nonce=request.POST.get('nonce', ''),
        auth_tag=request.POST.get('auth_tag', ''),
        original_size=int(request.POST.get('original_size', 0)),
        mime_type=request.POST.get('mime_type', 'application/octet-stream'),
    )
    return JsonResponse({
        'status': 'ok',
        'file_id': str(encrypted_file.id),
    })

def _get_accessible_file(request, file_id):
    file = EncryptedFile.objects.filter(id=file_id, owner=request.user).first()
    if file:
        return file
    share = FileShare.objects.filter(file_id=file_id, recipient=request.user, revoked=False).first()
    return share.file if share else None

@login_required
def download_file(request, file_id):
    encrypted_file = _get_accessible_file(request, file_id)
    if not encrypted_file:
        return JsonResponse({'error': 'File not found or access denied'}, status=404)
    response = HttpResponse(encrypted_file.ciphertext, content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment'
    response['X-File-Id'] = str(encrypted_file.id)
    response['X-Wrapped-Key'] = encrypted_file.wrapped_file_key
    response['X-Nonce'] = encrypted_file.nonce
    response['X-Auth-Tag'] = encrypted_file.auth_tag
    response['X-Encrypted-Filename'] = encrypted_file.encrypted_filename
    response['X-Encrypted-Metadata'] = encrypted_file.encrypted_metadata
    return response

@login_required
def download_file_data(request, file_id):
    encrypted_file = EncryptedFile.objects.filter(id=file_id, owner=request.user).first()
    if encrypted_file:
        EncryptedFile.objects.filter(id=encrypted_file.id).update(last_opened_at=timezone.now())
        return JsonResponse({
            'access': 'owner',
            'ciphertext': base64.b64encode(encrypted_file.ciphertext).decode('ascii'),
            'wrapped_file_key': encrypted_file.wrapped_file_key,
            'nonce': encrypted_file.nonce,
            'auth_tag': encrypted_file.auth_tag,
            'mime_type': encrypted_file.mime_type,
            'encrypted_filename': encrypted_file.encrypted_filename,
            'original_size': encrypted_file.original_size,
        })

    share = FileShare.objects.filter(file_id=file_id, recipient=request.user, revoked=False).first()
    if not share:
        return JsonResponse({'error': 'File not found or access denied'}, status=404)

    EncryptedFile.objects.filter(id=share.file_id).update(last_opened_at=timezone.now())

    return JsonResponse({
        'access': 'shared',
        'ciphertext': base64.b64encode(share.file.ciphertext).decode('ascii'),
        'wrapped_file_key': share.wrapped_file_key,
        'ephemeral_public_key': share.ephemeral_public_key,
        'nonce': share.file.nonce,
        'auth_tag': share.file.auth_tag,
        'mime_type': share.file.mime_type,
        'encrypted_filename': share.file.encrypted_filename,
        'original_size': share.file.original_size,
    })

@login_required
def file_detail(request, file_id):
    encrypted_file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    shares = FileShare.objects.filter(file=encrypted_file)
    return render(request, 'vault/file_detail.html', {
        'file': encrypted_file,
        'shares': shares,
    })

@login_required
@require_POST
def delete_file(request, file_id):
    encrypted_file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    encrypted_file.delete()
    return redirect('vault:dashboard')

@login_required
@require_POST
def rewrap_file_key(request, file_id):
    """Re-wrap a file's key under a new master key. The file ciphertext and
    any existing shares are untouched — the file key itself never changes."""
    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    data = json.loads(request.body)
    new_wrapped = data.get('wrapped_file_key', '')
    if not new_wrapped:
        return JsonResponse({'error': 'Missing wrapped_file_key'}, status=400)
    file.wrapped_file_key = new_wrapped
    file.save(update_fields=['wrapped_file_key'])
    return JsonResponse({'status': 'ok'})

@login_required
def file_list_api(request):
    files = EncryptedFile.objects.filter(owner=request.user)
    data = [{
        'id': str(f.id),
        'encrypted_filename': f.encrypted_filename,
        'encrypted_metadata': f.encrypted_metadata,
        'wrapped_file_key': f.wrapped_file_key,
        'nonce': f.nonce,
        'auth_tag': f.auth_tag,
        'original_size': f.original_size,
        'mime_type': f.mime_type,
        'uploaded_at': f.uploaded_at.isoformat(),
    } for f in files]
    return JsonResponse({'files': data})
