import json
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from .models import FileShare
from vault.models import EncryptedFile
from accounts.models import User

@login_required
def shared(request):
    shares = FileShare.objects.filter(recipient=request.user, revoked=False).select_related('owner', 'file')
    sent_shares = FileShare.objects.filter(owner=request.user).select_related('recipient', 'file').order_by('-created_at')
    return render(request, 'sharing/shared.html', {'shares': shares, 'sent_shares': sent_shares})

@login_required
def share_view(request, file_id):
    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    shares = FileShare.objects.filter(file=file)
    return render(request, 'sharing/share.html', {'file': file, 'shares': shares})

@login_required
@require_POST
def create_share(request):
    data = json.loads(request.body)
    file_id = data.get('file_id')
    recipient_username = data.get('recipient')

    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)
    try:
        recipient = User.objects.get(username=recipient_username)
    except User.DoesNotExist:
        try:
            recipient = User.objects.get(email=recipient_username)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Recipient not found'}, status=400)

    if recipient == request.user:
        return JsonResponse({'error': 'Cannot share with yourself'}, status=400)

    if not recipient.x25519_public_key:
        return JsonResponse({'error': 'Recipient has not set up encryption keys'}, status=400)

    share, created = FileShare.objects.get_or_create(
        file=file,
        recipient=recipient,
        defaults={
            'owner': request.user,
            'wrapped_file_key': data.get('wrapped_file_key', ''),
            'ephemeral_public_key': data.get('ephemeral_public_key', ''),
            'nonce': data.get('nonce', ''),
        }
    )
    if not created:
        return JsonResponse({'error': 'Already shared with this user'}, status=400)

    return JsonResponse({'status': 'ok', 'share_id': str(share.id)})

@login_required
@require_POST
def revoke_share(request, share_id):
    share = get_object_or_404(FileShare, id=share_id, owner=request.user)
    share.revoked = True
    share.save()
    return JsonResponse({'status': 'ok'})

@login_required
@require_POST
def re_encrypt_and_reshare(request):
    data = json.loads(request.body)
    file_id = data.get('file_id')

    file = get_object_or_404(EncryptedFile, id=file_id, owner=request.user)

    file.wrapped_file_key = data.get('new_wrapped_file_key', file.wrapped_file_key)
    file.ciphertext = bytes.fromhex(data.get('new_ciphertext_hex', '')) if data.get('new_ciphertext_hex') else file.ciphertext
    file.nonce = data.get('new_nonce', file.nonce)
    file.auth_tag = data.get('new_auth_tag', file.auth_tag)
    file.save()

    shares = FileShare.objects.filter(file=file, revoked=False)
    for share in shares:
        share.delete()

    return JsonResponse({'status': 'ok'})

@login_required
def lookup_user(request):
    query = request.GET.get('q', '')
    if not query:
        return JsonResponse({'users': []})
    users = User.objects.filter(username__icontains=query).exclude(id=request.user.id)[:10]
    data = [{
        'username': u.username,
        'email': u.email,
        'display_name': u.display_name,
        'x25519_public_key': u.x25519_public_key,
    } for u in users]
    return JsonResponse({'users': data})

@login_required
def shared_files_api(request):
    shares = FileShare.objects.filter(recipient=request.user, revoked=False)
    data = []
    for s in shares:
        data.append({
            'share_id': str(s.id),
            'file_id': str(s.file.id),
            'owner': s.owner.username,
            'wrapped_file_key': s.wrapped_file_key,
            'ephemeral_public_key': s.ephemeral_public_key,
            'nonce': s.nonce,
            'encrypted_filename': s.file.encrypted_filename,
            'encrypted_metadata': s.file.encrypted_metadata,
            'created_at': s.created_at.isoformat(),
        })
    return JsonResponse({'shares': data})
