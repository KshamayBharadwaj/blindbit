import json
import hashlib
import secrets
import time
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_http_methods
from django.http import JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from .models import User, Device

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

RP_ID = settings.WEBAUTHN_RP_ID
RP_NAME = settings.WEBAUTHN_RP_NAME


def get_rp_id(request):
    """Return RP ID that matches the current request host.

    The browser enforces that rp.id must be a registrable suffix of the
    current domain (e.g. spec SecurityError "Invalid domain"). The previous
    code used a static settings.WEBAUTHN_RP_ID='localhost', so visiting via
    http://127.0.0.1:8000 or any LAN/production host immediately failed with
    "Invalid domain" during navigator.credentials.create().

    This helper derives the RP ID from the request host for dev flexibility
    while still respecting an explicit production config (e.g.
    BLINDBIT_RP_ID=example.com allows subdomains like app.example.com).
    """
    try:
        host = request.get_host().split(":")[0].strip().lower()
    except Exception:
        host = ""
    configured = (settings.WEBAUTHN_RP_ID or "").strip().lower()
    # Respect explicit production RP ID if request is that domain or a subdomain
    if configured and configured != "localhost":
        if host == configured or host.endswith("." + configured):
            return configured
    # Empty / localhost config → use the actual host (covers localhost, 127.0.0.1, LAN IPs, etc.)
    if host:
        return host
    return configured or "localhost"


def get_rp_origin(request):
    return request.META.get('HTTP_ORIGIN') or f"{request.scheme}://{request.get_host()}"


def get_json_body(request):
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def register_view(request):
    if request.user.is_authenticated:
        return redirect('vault:dashboard')
    return render(request, 'accounts/register.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('vault:dashboard')
    return render(request, 'accounts/login.html')


def recovery_view(request):
    return render(request, 'accounts/recovery.html')


@require_POST
def registration_options(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()

    if not username or not email:
        return JsonResponse({'error': 'Username and email are required'}, status=400)

    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username already exists'}, status=400)
    if User.objects.filter(email=email).exists():
        return JsonResponse({'error': 'Email already exists'}, status=400)

    options = generate_registration_options(
        rp_id=get_rp_id(request),
        rp_name=RP_NAME,
        user_name=username,
        user_display_name=data.get('display_name', username),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    request.session['reg_challenge'] = bytes_to_base64url(options.challenge)
    request.session.modified = True

    return JsonResponse(json.loads(options_to_json(options)))


@require_POST
def register_complete(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()

    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username already exists'}, status=400)
    if User.objects.filter(email=email).exists():
        return JsonResponse({'error': 'Email already exists'}, status=400)

    expected_challenge_b64 = request.session.pop('reg_challenge', None)
    if not expected_challenge_b64:
        return JsonResponse({'error': 'No registration challenge. Please start over.'}, status=400)
    expected_challenge = base64url_to_bytes(expected_challenge_b64)

    cred_data = data.get('credential')
    if not cred_data:
        return JsonResponse({'error': 'Missing credential data'}, status=400)

    try:
        credential = RegistrationCredential(
            id=cred_data['id'],
            raw_id=base64url_to_bytes(cred_data['raw_id']),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(cred_data['response']['client_data_json']),
                attestation_object=base64url_to_bytes(cred_data['response']['attestation_object']),
            ),
            type='public-key',
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_rp_origin(request),
        )
    except Exception as e:
        return JsonResponse({'error': f'WebAuthn verification failed: {str(e)}'}, status=400)

    display_name = data.get('display_name', '')
    x25519_pub = data.get('x25519_public_key', '')
    x25519_enc_priv = data.get('encrypted_x25519_private_key', '')
    wrapped_mk_prf = data.get('wrapped_master_key_prf', '')
    prf_salt = data.get('prf_salt', '')
    wrapped_mk_pass = data.get('wrapped_master_key_passphrase', '')
    wrapped_mk_recovery = data.get('wrapped_master_key_recovery', '')
    passphrase_enabled = data.get('passphrase_enabled', False)
    passphrase_salt = data.get('passphrase_salt', '')
    device_name = data.get('device_name', '')

    passphrase_verifier = ''
    if wrapped_mk_pass:
        passphrase_verifier = hashlib.sha256(wrapped_mk_pass.encode()).hexdigest()

    user = User.objects.create_user(
        username=username,
        email=email,
        display_name=display_name,
        x25519_public_key=x25519_pub,
        encrypted_x25519_private_key=x25519_enc_priv,
        wrapped_master_key_prf=wrapped_mk_prf or '',
        prf_salt=prf_salt or '',
        wrapped_master_key_passphrase=wrapped_mk_pass or '',
        wrapped_master_key_recovery=wrapped_mk_recovery or '',
        passphrase_enabled=passphrase_enabled,
        passphrase_salt=passphrase_salt,
        passphrase_verifier=passphrase_verifier,
        is_onboarded=bool(wrapped_mk_recovery),
    )

    Device.objects.create(
        user=user,
        name=device_name or 'Unknown device',
        credential_id=cred_data['id'],
        public_key=bytes_to_base64url(verification.credential_public_key),
        prf_enabled=data.get('prf_enabled', False),
    )

    login(request, user)
    return JsonResponse({'status': 'ok', 'user_id': str(user.id)})


@require_POST
def login_begin(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    username = data.get('username', '').strip()

    if not username:
        return JsonResponse({'error': 'Username is required'}, status=400)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=400)

    # Only include credentials that have a stored public_key (can be verified)
    allow_credentials = []
    for device in user.devices.all():
        if device.credential_id and device.public_key:
            allow_credentials.append(PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(device.credential_id),
            ))

    has_passphrase = user.passphrase_enabled and bool(user.wrapped_master_key_passphrase)
    has_verified_credentials = len(allow_credentials) > 0

    result = {
        'has_passphrase': has_passphrase,
        'is_onboarded': user.is_onboarded,
        'has_verified_credentials': has_verified_credentials,
    }

    if has_passphrase:
        result['wrapped_master_key_passphrase'] = user.wrapped_master_key_passphrase
        result['passphrase_salt'] = user.passphrase_salt

    # PRF (prf-enabled passkey): the client can restore the master key from the
    # passkey itself, with no passphrase and no stored secrets on the device.
    if user.prf_salt and user.wrapped_master_key_prf:
        result['prf_enabled'] = True
        result['prf_salt'] = user.prf_salt
        result['wrapped_master_key_prf'] = user.wrapped_master_key_prf

    if has_verified_credentials:
        options = generate_authentication_options(
            rp_id=get_rp_id(request),
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        request.session['login_challenge'] = bytes_to_base64url(options.challenge)
        request.session['login_username'] = username
        request.session.modified = True

        options_dict = json.loads(options_to_json(options))
        options_dict.update(result)
        return JsonResponse(options_dict)

    # No verified credentials — passphrase only (legacy account)
    request.session['login_username'] = username
    request.session['login_legacy_no_pubkey'] = True
    request.session.modified = True

    return JsonResponse(result)


@require_POST
def login_complete(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)

    # Keep challenge/username in the session until verification succeeds so a
    # failed attempt can be retried without restarting the whole ceremony.
    username = request.session.get('login_username', '')
    expected_challenge_b64 = request.session.get('login_challenge')

    if not username or not expected_challenge_b64:
        return JsonResponse({'error': 'No login session. Please start over.'}, status=400)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=400)

    expected_challenge = base64url_to_bytes(expected_challenge_b64)

    cred_data = data.get('credential')
    if not cred_data:
        return JsonResponse({'error': 'Missing credential data'}, status=400)

    credential_id = cred_data.get('id', '')
    try:
        device = Device.objects.get(user=user, credential_id=credential_id)
    except Device.DoesNotExist:
        return JsonResponse({'error': 'Credential not recognized for this user'}, status=400)

    stored_pub_key = device.public_key
    if not stored_pub_key:
        return JsonResponse({'error': 'No public key stored for this device. Please re-register.'}, status=400)

    try:
        credential = AuthenticationCredential(
            id=credential_id,
            raw_id=base64url_to_bytes(cred_data['raw_id']),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(cred_data['response']['client_data_json']),
                authenticator_data=base64url_to_bytes(cred_data['response']['authenticator_data']),
                signature=base64url_to_bytes(cred_data['response']['signature']),
                user_handle=base64url_to_bytes(cred_data['response']['user_handle']) if cred_data['response'].get('user_handle') else None,
            ),
            type='public-key',
        )

        verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_rp_origin(request),
            credential_public_key=base64url_to_bytes(stored_pub_key),
            credential_current_sign_count=0,
        )
    except Exception as e:
        return JsonResponse({'error': f'WebAuthn verification failed: {str(e)}'}, status=400)

    request.session.pop('login_username', None)
    request.session.pop('login_challenge', None)

    login(request, user)
    return JsonResponse({
        'status': 'ok',
        'is_onboarded': user.is_onboarded,
        'wrapped_master_key_prf': user.wrapped_master_key_prf or '',
    })


@require_POST
def login_send_otp(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    username = data.get('username', '').strip()

    if not username:
        return JsonResponse({'error': 'Username is required'}, status=400)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=400)

    if not user.wrapped_master_key_passphrase:
        return JsonResponse({'error': 'No passphrase configured for this account'}, status=400)

    otp = f'{secrets.randbelow(1000000):06d}'
    request.session['login_otp'] = {
        'code': otp,
        'username': username,
        'expires_at': time.time() + 600,
    }
    request.session.modified = True

    send_mail(
        subject='Sign-In Verification Code — BlindBit',
        message=(
            f'A sign-in was attempted on your BlindBit account "{username}".\n\n'
            f'Your verification code is: {otp}\n\n'
            f'This code expires in 10 minutes.\n'
            f'If you did not request this, you can ignore this email.'
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    return JsonResponse({'status': 'otp_sent'})


@require_POST
def login_passphrase(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    username = data.get('username', '').strip()
    passphrase_verifier = data.get('passphrase_verifier', '').strip()
    otp = data.get('otp', '').strip()

    if not username:
        return JsonResponse({'error': 'Username is required'}, status=400)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=400)

    # Verify OTP
    otp_data = request.session.pop('login_otp', None)
    if not otp_data:
        return JsonResponse({'error': 'No OTP requested. Please request a verification code first.'}, status=400)
    if otp_data.get('username') != username:
        return JsonResponse({'error': 'OTP mismatch. Please request a new code.'}, status=400)
    if time.time() > otp_data.get('expires_at', 0):
        return JsonResponse({'error': 'OTP expired. Please request a new one.'}, status=400)
    if otp_data.get('code') != otp:
        return JsonResponse({'error': 'Invalid OTP. Please try again.'}, status=403)

    if not passphrase_verifier:
        return JsonResponse({'error': 'Passphrase verification required'}, status=400)

    # Verify passphrase: compute expected verifier from stored wrapped key
    if user.wrapped_master_key_passphrase:
        expected_verifier = hashlib.sha256(user.wrapped_master_key_passphrase.encode()).hexdigest()
        if passphrase_verifier != expected_verifier:
            return JsonResponse({'error': 'Invalid passphrase'}, status=403)
    elif user.passphrase_verifier:
        if passphrase_verifier != user.passphrase_verifier:
            return JsonResponse({'error': 'Invalid passphrase'}, status=403)
    else:
        return JsonResponse({'error': 'No passphrase configured for this account'}, status=400)

    device_name = data.get('device_name', '')
    if device_name:
        Device.objects.get_or_create(
            user=user,
            name=device_name,
            defaults={'prf_enabled': False},
        )

    login(request, user)
    return JsonResponse({
        'status': 'ok',
        'is_onboarded': user.is_onboarded,
        'wrapped_master_key_passphrase': user.wrapped_master_key_passphrase,
        'passphrase_salt': user.passphrase_salt,
    })


@login_required
@require_POST
def prf_upgrade_options(request):
    """Return a WebAuthn authentication challenge so the logged-in user can
    evaluate PRF on their existing passkey and wrap the master key for
    future passkey-only logins. No verification happens here — the user is
    already authenticated via session; the assertion is only used client-side
    to obtain the PRF output."""
    user = request.user
    allow_credentials = []
    for device in user.devices.all():
        if device.credential_id and device.public_key:
            allow_credentials.append(PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(device.credential_id),
            ))
    if not allow_credentials:
        return JsonResponse({'error': 'No passkey found for this account'}, status=400)
    options = generate_authentication_options(
        rp_id=get_rp_id(request),
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return JsonResponse(json.loads(options_to_json(options)))


@login_required
@require_POST
def enable_prf(request):
    """Save a PRF-wrapped master key for an existing account so future
    passkey logins restore the key with no passphrase. Server stores opaque
    ciphertext only (zero-knowledge preserved)."""
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    prf_salt = (data.get('prf_salt') or '').strip()
    wrapped = (data.get('wrapped_master_key_prf') or '').strip()
    credential_id = (data.get('credential_id') or '').strip()
    if not prf_salt or not wrapped:
        return JsonResponse({'error': 'Missing PRF key material'}, status=400)
    # Basic sanity: hex salt, base64 wrapped blob
    if len(prf_salt) != 64 or any(c not in '0123456789abcdefABCDEF' for c in prf_salt):
        return JsonResponse({'error': 'Invalid PRF salt'}, status=400)
    user = request.user
    user.prf_salt = prf_salt.lower()
    user.wrapped_master_key_prf = wrapped
    user.save(update_fields=['prf_salt', 'wrapped_master_key_prf'])
    if credential_id:
        Device.objects.filter(user=user, credential_id=credential_id).update(prf_enabled=True)
    else:
        # Fallback: mark the most recently used device
        latest = user.devices.order_by('-last_used').first()
        if latest:
            latest.prf_enabled = True
            latest.save(update_fields=['prf_enabled'])
    return JsonResponse({'status': 'ok'})


@login_required
@require_POST
def add_device_options(request):
    user = request.user
    options = generate_registration_options(
        rp_id=get_rp_id(request),
        rp_name=RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.display_name or user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    request.session['add_device_challenge'] = bytes_to_base64url(options.challenge)
    request.session.modified = True

    result = json.loads(options_to_json(options))
    result['wrapped_master_key_passphrase'] = user.wrapped_master_key_passphrase or ''
    result['passphrase_salt'] = user.passphrase_salt or ''
    return JsonResponse(result)


@login_required
@require_POST
def add_device_complete(request):
    data = json.loads(request.body)
    challenge_b64 = request.session.pop('add_device_challenge', None)
    if not challenge_b64:
        return JsonResponse({'error': 'No registration challenge. Please start over.'}, status=400)

    challenge = base64url_to_bytes(challenge_b64)
    cred_data = data.get('credential')
    if not cred_data:
        return JsonResponse({'error': 'Missing credential data'}, status=400)

    try:
        credential = RegistrationCredential(
            id=cred_data['id'],
            raw_id=base64url_to_bytes(cred_data['raw_id']),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(cred_data['response']['client_data_json']),
                attestation_object=base64url_to_bytes(cred_data['response']['attestation_object']),
            ),
            type='public-key',
        )
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_rp_origin(request),
        )
    except Exception as e:
        return JsonResponse({'error': f'WebAuthn verification failed: {str(e)}'}, status=400)

    device = Device.objects.create(
        user=request.user,
        name=data.get('device_name', 'Unknown device'),
        credential_id=cred_data['id'],
        public_key=bytes_to_base64url(verification.credential_public_key),
        prf_enabled=data.get('prf_enabled', False),
        wrapped_master_key=data.get('wrapped_master_key', ''),
    )
    return JsonResponse({'status': 'ok', 'device_id': str(device.id)})


@login_required
@require_POST
def keys_setup(request):
    """Restore/setup flow for accounts that predate the master-key system.
    Rebuilds the full key chain in the browser and stores it: recovery-wrapped
    master key, optional passphrase-wrapped master key, and X25519 keys."""
    data = json.loads(request.body)
    user = request.user

    wrapped_mk_recovery = data.get('wrapped_master_key_recovery', '')
    wrapped_mk_pass = data.get('wrapped_master_key_passphrase', '')
    passphrase_salt = data.get('passphrase_salt', '')
    passphrase_enabled = data.get('passphrase_enabled', False)
    x25519_pub = data.get('x25519_public_key', '')
    x25519_enc_priv = data.get('encrypted_x25519_private_key', '')

    if not wrapped_mk_recovery or not x25519_pub or not x25519_enc_priv:
        return JsonResponse({'error': 'Missing required key material'}, status=400)

    passphrase_verifier = ''
    if wrapped_mk_pass:
        passphrase_verifier = hashlib.sha256(wrapped_mk_pass.encode()).hexdigest()

    user.wrapped_master_key_recovery = wrapped_mk_recovery
    user.wrapped_master_key_passphrase = wrapped_mk_pass
    user.passphrase_salt = passphrase_salt
    user.passphrase_enabled = passphrase_enabled
    user.passphrase_verifier = passphrase_verifier
    user.x25519_public_key = x25519_pub
    user.encrypted_x25519_private_key = x25519_enc_priv
    user.recovery_phrase_confirmed = True
    user.is_onboarded = True
    user.save()
    return JsonResponse({'status': 'ok'})


def logout_view(request):
    logout(request)
    return redirect('landing')


@login_required
@require_http_methods(['GET', 'POST'])
def my_keys(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        request.user.x25519_public_key = data.get('x25519_public_key', request.user.x25519_public_key)
        request.user.encrypted_x25519_private_key = data.get('encrypted_x25519_private_key', request.user.encrypted_x25519_private_key)
        request.user.save(update_fields=['x25519_public_key', 'encrypted_x25519_private_key'])
        return JsonResponse({'status': 'ok'})
    return JsonResponse({
        'x25519_public_key': request.user.x25519_public_key or '',
        'encrypted_x25519_private_key': request.user.encrypted_x25519_private_key or '',
    })


@login_required
def devices_view(request):
    devices = request.user.devices.all()
    return render(request, 'accounts/devices.html', {'devices': devices})


@login_required
@require_POST
def send_remove_otp(request, device_id):
    try:
        device = request.user.devices.get(id=device_id)
    except Device.DoesNotExist:
        return JsonResponse({'error': 'Device not found'}, status=404)

    otp = f'{secrets.randbelow(1000000):06d}'
    request.session['remove_otp'] = {
        'code': otp,
        'device_id': str(device.id),
        'expires_at': time.time() + 600,
    }
    request.session.modified = True

    send_mail(
        subject='Remove Trusted Device — BlindBit',
        message=(
            f'A request was made to remove the device "{device.name}" '
            f'from your BlindBit account.\n\n'
            f'Your one-time code is: {otp}\n\n'
            f'This code expires in 10 minutes.\n'
            f'If you did not request this, you can ignore this email.'
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[request.user.email],
        fail_silently=False,
    )
    return JsonResponse({'status': 'otp_sent'})


@login_required
@require_POST
def verify_remove_device(request, device_id):
    data = json.loads(request.body)
    otp_data = request.session.get('remove_otp')

    if not otp_data:
        return JsonResponse({'error': 'No OTP requested. Please try again.'}, status=400)

    if otp_data['device_id'] != str(device_id):
        return JsonResponse({'error': 'OTP mismatch. Please try again.'}, status=400)

    if time.time() > otp_data['expires_at']:
        del request.session['remove_otp']
        request.session.modified = True
        return JsonResponse({'error': 'OTP expired. Please request a new one.'}, status=400)

    if otp_data['code'] != data.get('otp', ''):
        return JsonResponse({'error': 'Invalid OTP. Please try again.'}, status=400)

    del request.session['remove_otp']
    request.session.modified = True

    try:
        device = request.user.devices.get(id=device_id)
        device.delete()
        return JsonResponse({'status': 'ok'})
    except Device.DoesNotExist:
        return JsonResponse({'error': 'Device not found'}, status=404)


@login_required
@require_POST
def confirm_recovery(request):
    data = json.loads(request.body)
    wrapped_mk_recovery = data.get('wrapped_master_key_recovery', '')
    request.user.recovery_phrase_confirmed = True
    request.user.is_onboarded = True
    if wrapped_mk_recovery:
        request.user.wrapped_master_key_recovery = wrapped_mk_recovery
    request.user.save()
    return JsonResponse({'status': 'ok'})
