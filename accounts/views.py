import json
import hashlib
import secrets
import time
from functools import wraps
from urllib.parse import urlparse
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

LOOPBACK_ALIASES = {'127.0.0.1', '::1', '[::1]', '0.0.0.0'}
CEREMONY_TTL_SECONDS = 300
MAX_ACTIVE_CEREMONIES = 10


def _host_and_port(request):
    """Split ``request.get_host()`` into a lowercase host and its port."""
    netloc = request.get_host().strip().lower()
    if netloc.startswith('['):
        host, _, rest = netloc[1:].partition(']')
        return host, rest.lstrip(':')
    if ':' in netloc:
        host, port = netloc.split(':', 1)
        return host, port
    return netloc, ''


def get_rp_id(request):
    """The RP ID for this request.

    A browser only accepts an rp.id that is a registrable suffix of the host
    serving the page, and a passkey is cryptographically bound to the rp.id it
    was created under, so the ID follows the request host in development
    (localhost, 127.0.0.1, LAN IPs) and is pinned to BLINDBIT_RP_ID once a real
    domain is configured.
    """
    host, _ = _host_and_port(request)
    configured = (settings.WEBAUTHN_RP_ID or '').strip().lower()
    if configured and configured != 'localhost':
        if host == configured or host.endswith('.' + configured):
            return configured
    if host:
        return host
    return configured or 'localhost'


def canonical_host_redirect(request):
    """Move a loopback-IP visit onto ``localhost``.

    ``localhost`` and ``127.0.0.1`` are different RP IDs, so a passkey created
    under one is unreachable under the other and sign-in appears to work only
    on whichever address the user happened to use. Loopback is development
    only, so collapse it to a single passkey realm.
    """
    if (settings.WEBAUTHN_RP_ID or 'localhost').strip().lower() != 'localhost':
        return None
    host, port = _host_and_port(request)
    if host == 'localhost' or host not in LOOPBACK_ALIASES:
        return None
    netloc = f'localhost:{port}' if port else 'localhost'
    return redirect(f'{request.scheme}://{netloc}{request.get_full_path()}')


def get_rp_origins(request):
    """Every origin a response for this request could legitimately come from.

    clientDataJSON carries the browser's own origin, which does not always
    match the URL Django sees once a TLS terminator rewrites the scheme or drops
    a default port, so verification accepts the set instead of one guess.
    """
    host = request.get_host()
    origins = [f'{request.scheme}://{host}']

    def add(candidate):
        candidate = (candidate or '').strip().rstrip('/')
        if candidate and candidate not in origins:
            origins.append(candidate)

    add(request.META.get('HTTP_ORIGIN'))
    forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', '').split(',')[0].strip()
    if forwarded_proto:
        add(f'{forwarded_proto}://{host}')
    configured = (settings.WEBAUTHN_RP_ORIGIN or '').strip()
    if configured and urlparse(configured).netloc.lower() == host.lower():
        add(configured)
    return origins


def get_json_body(request):
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def store_ceremony(request, kind, challenge, username=''):
    """Remember an in-flight challenge, returning the token that claims it.

    Challenges used to occupy one session slot each, so a second tab, the
    passphrase tab, or the dashboard's unlock prompt (all of which call
    login_begin) overwrote the challenge of a ceremony the user was still
    finishing in the authenticator prompt.
    """
    now = time.time()
    store = {key: value for key, value in (request.session.get('ceremonies') or {}).items()
             if value.get('exp', 0) > now}

    token = secrets.token_urlsafe(16)
    store[token] = {
        'kind': kind,
        'challenge': bytes_to_base64url(challenge),
        'username': username,
        'exp': now + CEREMONY_TTL_SECONDS,
    }
    while len(store) > MAX_ACTIVE_CEREMONIES:
        oldest = min(store, key=lambda key: store[key]['exp'])
        del store[oldest]

    request.session['ceremonies'] = store
    request.session.modified = True
    return token


def consume_ceremony(request, kind, token):
    """Return ``(username, challenge)`` for a token, or None if it is stale.

    Tokens are single-use, so one ceremony can never consume another's
    challenge.
    """
    store = request.session.get('ceremonies') or {}
    entry = store.pop(token or '', None)
    request.session['ceremonies'] = store
    request.session.modified = True

    if not entry or entry.get('kind') != kind or entry.get('exp', 0) < time.time():
        return None
    return entry.get('username', ''), base64url_to_bytes(entry['challenge'])


STALE_CEREMONY = {'error': 'that passkey request expired or was already used. start the sign-in again.'}


def json_login_required(view):
    """``@login_required`` for the JSON endpoints.

    A signed-out browser fetch() would otherwise receive the HTML login page and
    report it as a passkey failure, so an ended session is answered as one.
    """
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'your session ended. sign in again, then retry.'}, status=401)
        return view(request, *args, **kwargs)
    return wrapper


def _b64_field(data, *path):
    missing = '.'.join(path)
    node = data
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise ValueError(f'missing credential field "{missing}"')
        node = node[key]
    if not isinstance(node, str):
        raise ValueError(f'credential field "{missing}" must be base64')
    try:
        return base64url_to_bytes(node)
    except Exception as exc:
        raise ValueError(f'credential field "{missing}" is not valid base64') from exc


def _registration_credential(cred_data):
    if not isinstance(cred_data, dict) or not isinstance(cred_data.get('id'), str):
        raise ValueError('credential.id is missing')
    return RegistrationCredential(
        id=cred_data['id'],
        raw_id=_b64_field(cred_data, 'raw_id'),
        response=AuthenticatorAttestationResponse(
            client_data_json=_b64_field(cred_data, 'response', 'client_data_json'),
            attestation_object=_b64_field(cred_data, 'response', 'attestation_object'),
        ),
        type='public-key',
    )


def _authentication_credential(cred_data):
    if not isinstance(cred_data, dict) or not isinstance(cred_data.get('id'), str):
        raise ValueError('credential.id is missing')
    user_handle = None
    if isinstance(cred_data.get('response'), dict) and cred_data['response'].get('user_handle'):
        user_handle = _b64_field(cred_data, 'response', 'user_handle')
    return AuthenticationCredential(
        id=cred_data['id'],
        raw_id=_b64_field(cred_data, 'raw_id'),
        response=AuthenticatorAssertionResponse(
            client_data_json=_b64_field(cred_data, 'response', 'client_data_json'),
            authenticator_data=_b64_field(cred_data, 'response', 'authenticator_data'),
            signature=_b64_field(cred_data, 'response', 'signature'),
            user_handle=user_handle,
        ),
        type='public-key',
    )


def _descriptor(credential_id):
    """A WebAuthn descriptor for a stored credential ID, or None.

    One unreadable row would otherwise raise inside login_begin and break every
    sign-in attempt for the account.
    """
    try:
        return PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))
    except Exception:
        return None


def _credentials_matching(user, rp_id):
    """This user's usable passkeys, and how many belong to another host.

    Offering a credential whose rp.id does not match the page only produces an
    opaque NotAllowedError in the browser, so the mismatch is reported instead.
    """
    usable, elsewhere = [], 0
    for device in user.devices.all():
        if not device.credential_id or not device.public_key:
            continue
        if device.rp_id and device.rp_id != rp_id:
            elsewhere += 1
            continue
        usable.append(device)
    return usable, elsewhere


def _device_for_credential(user, cred_data):
    """The device row a signing-in credential belongs to, or None.

    Credential IDs are opaque bytes with more than one legal base64 spelling,
    and older rows were saved straight from the browser's string, so the decoded
    values are compared instead of the encodings. Matching on the raw string
    silently failed for those rows and the passkey looked unregistered.
    """
    raw = cred_data.get('raw_id') or cred_data.get('id')
    try:
        wanted = base64url_to_bytes(raw)
    except Exception:
        return None
    for device in user.devices.exclude(public_key=''):
        try:
            if base64url_to_bytes(device.credential_id) == wanted:
                return device
        except Exception:
            continue
    return None


def _device_unlocks_vault(user, device, passkey_count):
    """Whether this passkey alone can restore the master key.

    PRF output is per credential, so a wrapped master key only fits the passkey
    that produced it. The account-level column predates that and is only safe to
    use when the account has exactly one passkey — otherwise a newer one would
    unwrap garbage and leave the vault locked after a successful sign-in.
    """
    if not user.prf_salt:
        return False
    if device.wrapped_master_key:
        return True
    return bool(user.wrapped_master_key_prf) and passkey_count == 1


def register_view(request):
    forwarded = canonical_host_redirect(request)
    if forwarded:
        return forwarded
    if request.user.is_authenticated:
        return redirect('vault:dashboard')
    return render(request, 'accounts/register.html')


def login_view(request):
    forwarded = canonical_host_redirect(request)
    if forwarded:
        return forwarded
    if request.user.is_authenticated:
        return redirect('vault:dashboard')
    return render(request, 'accounts/login.html')


def recovery_view(request):
    forwarded = canonical_host_redirect(request)
    if forwarded:
        return forwarded
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

    ceremony = store_ceremony(request, 'register', options.challenge, username)

    payload = json.loads(options_to_json(options))
    payload['ceremony'] = ceremony
    return JsonResponse(payload)


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

    consumed = consume_ceremony(request, 'register', data.get('ceremony'))
    if not consumed:
        return JsonResponse(STALE_CEREMONY, status=400)
    ceremony_username, expected_challenge = consumed
    if ceremony_username != username:
        return JsonResponse({'error': 'the username changed since the passkey was created. start over.'}, status=400)

    cred_data = data.get('credential')
    if not cred_data:
        return JsonResponse({'error': 'Missing credential data'}, status=400)

    try:
        credential = _registration_credential(cred_data)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_rp_origins(request),
            # Only demanded when the client claims PRF material, since an
            # authenticator that cannot verify must still be able to enrol.
            require_user_verification=bool(data.get('wrapped_master_key_prf')),
        )
    except ValueError as e:
        return JsonResponse({'error': f'Malformed passkey response: {str(e)}'}, status=400)
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
        # Store the ID the verifier confirmed rather than the browser's string,
        # so every later credential lookup compares the same bytes.
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=bytes_to_base64url(verification.credential_public_key),
        rp_id=get_rp_id(request),
        prf_enabled=data.get('prf_enabled', False),
        wrapped_master_key=wrapped_mk_prf or '',
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

    rp_id = get_rp_id(request)
    usable_devices, credentials_on_other_hosts = _credentials_matching(user, rp_id)
    allow_credentials = [
        descriptor for descriptor in
        (_descriptor(device.credential_id) for device in usable_devices)
        if descriptor
    ]
    passkey_count = user.devices.exclude(public_key='').count()

    has_passphrase = user.passphrase_enabled and bool(user.wrapped_master_key_passphrase)

    # A passkey can only restore the master key when the PRF salt survived and
    # this particular credential has a master key wrapped with its own PRF
    # output.
    unlockable = [device for device in usable_devices
                  if _device_unlocks_vault(user, device, passkey_count)]
    prf_available = bool(unlockable)

    result = {
        'has_passphrase': has_passphrase,
        'is_onboarded': user.is_onboarded,
        'has_verified_credentials': bool(allow_credentials),
        'passkey_unlocks_vault': prf_available,
    }

    if credentials_on_other_hosts and not allow_credentials:
        result['credentials_on_other_hosts'] = True

    if has_passphrase:
        result['wrapped_master_key_passphrase'] = user.wrapped_master_key_passphrase
        result['passphrase_salt'] = user.passphrase_salt

    if prf_available:
        result['prf_enabled'] = True
        result['prf_salt'] = user.prf_salt

    if allow_credentials:
        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            # An authenticator only hands out PRF output for a verified user;
            # leaving verification "preferred" makes the master key restore fail
            # silently on whichever passkey happens to skip it. Only insist on
            # it when every passkey on offer is expected to unlock the vault, so
            # an account that is merely passing through the login step is never
            # blocked by an authenticator that cannot verify.
            user_verification=(UserVerificationRequirement.REQUIRED
                               if len(unlockable) == len(usable_devices)
                               else UserVerificationRequirement.PREFERRED),
        )

        ceremony = store_ceremony(request, 'login', options.challenge, username)

        payload = json.loads(options_to_json(options))
        payload.update(result)
        payload['ceremony'] = ceremony
        return JsonResponse(payload)

    # No usable credentials — passphrase or recovery only
    return JsonResponse(result)


@require_POST
def login_complete(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)

    consumed = consume_ceremony(request, 'login', data.get('ceremony'))
    if not consumed:
        return JsonResponse(STALE_CEREMONY, status=400)
    username, expected_challenge = consumed

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=400)

    cred_data = data.get('credential')
    if not isinstance(cred_data, dict) or not cred_data.get('id'):
        return JsonResponse({'error': 'Missing credential data'}, status=400)

    device = _device_for_credential(user, cred_data)
    if not device:
        return JsonResponse({'error': 'this passkey is not registered on the account you are signing into'}, status=400)

    prf_available = _device_unlocks_vault(user, device, user.devices.exclude(public_key='').count())

    try:
        credential = _authentication_credential(cred_data)
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_rp_origins(request),
            credential_public_key=base64url_to_bytes(device.public_key),
            credential_current_sign_count=0,
            require_user_verification=prf_available,
        )
    except ValueError as e:
        return JsonResponse({'error': f'Malformed passkey response: {str(e)}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'WebAuthn verification failed: {str(e)}'}, status=400)

    device.save(update_fields=['last_used'])

    login(request, user)
    return JsonResponse({
        'status': 'ok',
        'is_onboarded': user.is_onboarded,
        'has_passphrase': bool(user.passphrase_enabled and user.wrapped_master_key_passphrase),
        'passkey_unlocks_vault': prf_available,
        # The PRF output is per credential, so the wrapped key has to come from
        # the device that just signed in, not from the account as a whole.
        'wrapped_master_key': (device.wrapped_master_key or user.wrapped_master_key_prf) if prf_available else '',
        'credential_id': device.credential_id,
        'user_verified': verified.user_verified,
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


@json_login_required
@require_POST
def prf_upgrade_options(request):
    """Return a WebAuthn authentication challenge so the logged-in user can
    evaluate PRF on their existing passkey and wrap the master key for
    future passkey-only logins. No verification happens here — the user is
    already authenticated via session; the assertion is only used client-side
    to obtain the PRF output."""
    usable_devices, elsewhere = _credentials_matching(request.user, get_rp_id(request))
    if not usable_devices:
        detail = ' created on a different host' if elsewhere else ''
        return JsonResponse({'error': f'no passkey on this account{detail} can be used here'}, status=400)
    options = generate_authentication_options(
        rp_id=get_rp_id(request),
        allow_credentials=[descriptor for descriptor in
                           (_descriptor(device.credential_id) for device in usable_devices)
                           if descriptor],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return JsonResponse(json.loads(options_to_json(options)))


@json_login_required
@require_POST
def enable_prf(request):
    """Bind a PRF-wrapped master key to one passkey so that passkey unlocks the
    vault with no passphrase. The server stores opaque ciphertext only (zero-
    knowledge preserved).

    Each credential produces its own PRF output, so the wrapped key belongs to
    the device, while the HKDF salt stays account-wide because login_begin is
    what hands it to the client before the ceremony runs.
    """
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    prf_salt = (data.get('prf_salt') or '').strip().lower()
    wrapped = (data.get('wrapped_master_key') or data.get('wrapped_master_key_prf') or '').strip()
    credential_id = (data.get('credential_id') or '').strip()
    if not prf_salt or not wrapped:
        return JsonResponse({'error': 'Missing PRF key material'}, status=400)
    if len(prf_salt) != 64 or any(c not in '0123456789abcdef' for c in prf_salt):
        return JsonResponse({'error': 'Invalid PRF salt'}, status=400)

    user = request.user
    if user.prf_salt and user.prf_salt != prf_salt:
        return JsonResponse({'error': 'this account already uses a different PRF salt'}, status=400)

    device = None
    if credential_id:
        device = _device_for_credential(user, {'id': credential_id})
        if not device:
            return JsonResponse({'error': 'that passkey is not registered on this account'}, status=400)

    if device:
        device.wrapped_master_key = wrapped
        device.prf_enabled = True
        device.save(update_fields=['wrapped_master_key', 'prf_enabled'])
    else:
        user.prf_salt = prf_salt
        user.wrapped_master_key_prf = wrapped
        user.save(update_fields=['prf_salt', 'wrapped_master_key_prf'])
        latest = user.devices.filter(public_key__gt='').order_by('-last_used').first()
        if latest:
            latest.prf_enabled = True
            latest.save(update_fields=['prf_enabled'])

    if not user.prf_salt:
        user.prf_salt = prf_salt
        user.save(update_fields=['prf_salt'])

    return JsonResponse({'status': 'ok', 'credential_id': device.credential_id if device else ''})


@json_login_required
@require_POST
def add_device_options(request):
    user = request.user
    options = generate_registration_options(
        rp_id=get_rp_id(request),
        rp_name=RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.display_name or user.username,
        # Stops the same passkey being enrolled twice, which would leave two
        # rows for one credential id and make sign-in ambiguous.
        exclude_credentials=[descriptor for descriptor in
                             (_descriptor(device.credential_id)
                              for device in user.devices.exclude(credential_id=''))
                             if descriptor],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    ceremony = store_ceremony(request, 'device', options.challenge, user.username)

    result = json.loads(options_to_json(options))
    result['ceremony'] = ceremony
    result['wrapped_master_key_passphrase'] = user.wrapped_master_key_passphrase or ''
    result['passphrase_salt'] = user.passphrase_salt or ''
    # Shared account salt: every passkey wraps the master key with its own PRF
    # output, but the salt stays the same so login_begin has one value to offer.
    result['prf_salt'] = user.prf_salt or ''
    return JsonResponse(result)


@json_login_required
@require_POST
def add_device_complete(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)

    consumed = consume_ceremony(request, 'device', data.get('ceremony'))
    if not consumed:
        return JsonResponse(STALE_CEREMONY, status=400)
    _, challenge = consumed

    cred_data = data.get('credential')
    if not cred_data:
        return JsonResponse({'error': 'Missing credential data'}, status=400)

    # login_begin hands out one account-wide salt before it knows which
    # credential will sign in, so a newly enrolled passkey has to reuse it.
    wrapped = data.get('wrapped_master_key', '')
    prf_salt = (data.get('prf_salt') or '').strip().lower()
    if wrapped:
        if len(prf_salt) != 64 or any(c not in '0123456789abcdef' for c in prf_salt):
            return JsonResponse({'error': 'Invalid PRF salt'}, status=400)
        if request.user.prf_salt and request.user.prf_salt != prf_salt:
            return JsonResponse({'error': 'this account already uses a different PRF salt'}, status=400)

    try:
        credential = _registration_credential(cred_data)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(request),
            expected_origin=get_rp_origins(request),
            require_user_verification=True,
        )
    except ValueError as e:
        return JsonResponse({'error': f'Malformed passkey response: {str(e)}'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'WebAuthn verification failed: {str(e)}'}, status=400)

    device = Device.objects.create(
        user=request.user,
        name=data.get('device_name', 'Unknown device'),
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=bytes_to_base64url(verification.credential_public_key),
        rp_id=get_rp_id(request),
        prf_enabled=bool(wrapped),
        wrapped_master_key=wrapped,
    )

    if wrapped and not request.user.prf_salt:
        request.user.prf_salt = prf_salt
        request.user.save(update_fields=['prf_salt'])

    return JsonResponse({'status': 'ok', 'device_id': str(device.id)})


@json_login_required
@require_POST
def keys_setup(request):
    """Restore/setup flow for accounts that predate the master-key system.
    Rebuilds the full key chain in the browser and stores it: recovery-wrapped
    master key, optional passphrase-wrapped master key, and X25519 keys."""
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
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
    # This is a brand new master key, so every passkey-wrapped copy of the old
    # one is now garbage: leaving them in place advertises a passkey unlock
    # that restores a key nothing decrypts.
    user.prf_salt = ''
    user.wrapped_master_key_prf = ''
    user.save()
    user.devices.update(wrapped_master_key='', prf_enabled=False)
    return JsonResponse({'status': 'ok'})


def logout_view(request):
    logout(request)
    return redirect('landing')


@json_login_required
@require_http_methods(['GET', 'POST'])
def my_keys(request):
    if request.method == 'POST':
        data = get_json_body(request)
        if data is None:
            return JsonResponse({'error': 'Invalid request body'}, status=400)
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
    forwarded = canonical_host_redirect(request)
    if forwarded:
        return forwarded
    rp_id = get_rp_id(request)
    devices = list(request.user.devices.all())
    passkey_count = len([d for d in devices if d.public_key])
    for device in devices:
        # Whether this passkey alone restores the vault, so the list can say so
        # honestly instead of trusting a flag that can predate the wrapped key.
        device.can_unlock = _device_unlocks_vault(request.user, device, passkey_count)
    return render(request, 'accounts/devices.html', {
        'devices': devices,
        'rp_id': rp_id,
        'foreign_devices': [d for d in devices if d.rp_id and d.rp_id != rp_id],
    })


@json_login_required
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


@json_login_required
@require_POST
def verify_remove_device(request, device_id):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
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


@json_login_required
@require_POST
def confirm_recovery(request):
    data = get_json_body(request)
    if data is None:
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    wrapped_mk_recovery = data.get('wrapped_master_key_recovery', '')
    request.user.recovery_phrase_confirmed = True
    request.user.is_onboarded = True
    if wrapped_mk_recovery:
        request.user.wrapped_master_key_recovery = wrapped_mk_recovery
    request.user.save()
    return JsonResponse({'status': 'ok'})
