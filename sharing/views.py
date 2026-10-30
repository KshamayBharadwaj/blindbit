import json
from uuid import UUID
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from .models import FileShare
from vault.models import EncryptedFile
from accounts.models import User

BAD_BODY = 'Malformed request body.'
BAD_ID = 'That file is no longer yours. Reload the page and try again.'


def get_json_body(request):
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _uuid(value):
    """Parse an id that arrived in a request body; URL ids are validated by the
    route converter, body ids are not."""
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError):
        return None


def _bad_request(message=BAD_BODY):
    return JsonResponse({'error': message}, status=400)


def _owned_file(request, file_id):
    """Return (file, error) for a body-supplied file id owned by the caller."""
    clean = _uuid(file_id)
    file = EncryptedFile.objects.filter(id=clean, owner=request.user).first() if clean else None
    if file is None:
        return None, JsonResponse({'error': BAD_ID}, status=400)
    return file, None

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
    data = get_json_body(request)
    if data is None:
        return _bad_request()
    recipient_username = data.get('recipient')

    file, error = _owned_file(request, data.get('file_id'))
    if error:
        return error
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

    material = {name: data.get(name, '') for name in ('wrapped_file_key', 'ephemeral_public_key', 'nonce')}
    if any(not isinstance(value, str) for value in material.values()):
        return _bad_request('The wrapped key material must be text.')

    share = FileShare.objects.filter(file=file, recipient=recipient).first()
    if share:
        if not share.revoked:
            return JsonResponse({'error': 'Already shared with this user'}, status=400)
        share.wrapped_file_key = material['wrapped_file_key']
        share.ephemeral_public_key = material['ephemeral_public_key']
        share.nonce = material['nonce']
        share.revoked = False
        share.save()
        return JsonResponse({'status': 'ok', 'share_id': str(share.id)})

    share = FileShare.objects.create(
        file=file,
        owner=request.user,
        recipient=recipient,
        **material,
    )
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
def delete_share(request, share_id):
    share = get_object_or_404(FileShare, id=share_id, owner=request.user)
    share.delete()
    return JsonResponse({'status': 'ok'})

@login_required
@require_POST
def re_encrypt_and_reshare(request):
    data = get_json_body(request)
    if data is None:
        return _bad_request()

    file, error = _owned_file(request, data.get('file_id'))
    if error:
        return error

    new_ciphertext = data.get('new_ciphertext_hex', '')
    if new_ciphertext and not isinstance(new_ciphertext, str):
        return _bad_request('The replacement ciphertext must be hex text.')
    try:
        ciphertext_bytes = bytes.fromhex(new_ciphertext) if new_ciphertext else file.ciphertext
    except ValueError:
        return _bad_request('The replacement ciphertext is not valid hex.')

    file.wrapped_file_key = data.get('new_wrapped_file_key', file.wrapped_file_key)
    file.ciphertext = ciphertext_bytes
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
