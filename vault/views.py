import json
import base64
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponse
from .models import EncryptedFile
from sharing.models import FileShare

@login_required
def dashboard(request):
    my_files = EncryptedFile.objects.filter(owner=request.user)
    shared_with_me = FileShare.objects.filter(recipient=request.user, revoked=False)
    return render(request, 'vault/dashboard.html', {
        'files': my_files,
        'shared_files': shared_with_me,
    })

@login_required
def upload_view(request):
    return render(request, 'vault/upload.html')

@login_required
@require_POST
def upload_file(request):
    ciphertext = request.FILES.get('ciphertext')
    if not ciphertext:
        return JsonResponse({'error': 'No ciphertext provided'}, status=400)

    if ciphertext.size > 104857600:
        return JsonResponse({'error': 'File exceeds 100MB limit'}, status=400)

    encrypted_file = EncryptedFile.objects.create(
        owner=request.user,
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

    return JsonResponse({
        'access': 'shared',
        'ciphertext': base64.b64encode(share.file.ciphertext).decode('ascii'),
        'wrapped_file_key': share.wrapped_file_key,
        'ephemeral_public_key': share.ephemeral_public_key,
        'nonce': share.nonce,
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
