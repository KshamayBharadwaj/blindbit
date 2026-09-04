# AGENTS.md

BlindBit = Django 6 app (`blindbit` project) that is a **zero-knowledge encrypted cloud vault**. All file/master-key crypto happens in the browser; the server stores ciphertext and wrapped keys only.

## Run
- Python env lives in `venv/` (Python 3.12). Use it explicitly:
  - `venv/bin/python manage.py runserver` (dev server on `:8000`)
  - `venv/bin/python manage.py makemigrations` / `migrate`
  - `venv/bin/python manage.py createsuperuser`
- Admin UI is **django-unfold** at `/admin/`.
- No test suite, no lint/format config, no CI exists. Don't invent commands for them.

## Architecture
- Custom user model: `AUTH_USER_MODEL = 'accounts.User'` (UUID PK — **never** change this). Use `settings.AUTH_USER_MODEL` or `get_user_model()`, not auth.User.
- Three apps:
  - `accounts` — WebAuthn passkeys + passphrase fallback + device management (OTP-gated removal). RP config under `WEBAUTHN_*` env vars.
  - `vault` — `EncryptedFile`, `VaultFolder` (incl. auto `is_favorites` smart folder), chunked `UploadSession`/`FileChunk`, soft-delete trash. 8 MB chunks (`CHUNK_SIZE`).
  - `sharing` — `FileShare` via X25519 ECDH re-wrap of the file key.
- `/` landing and `/docs/` are rendered by Django `TemplateView` from `templates/`.

## Critical gotchas
- **Do not implement file/master-key key derivation or encryption on the server.** That violates the zero-knowledge design. Crypto logic lives in `static/js/crypto.js` (`BlindBitCrypto`, `BlindBitX25519` pure-JS, no deps). Views only store/forward opaque ciphertext and wrapped keys.
- `EncryptedFile` has two managers: `objects` (default, **excludes** trashed) and `all_objects`. Any trash/restore/purge query must use `all_objects` (see `vault/views.py` and `purge_trash`).
- Landing page: `templates/index.html` is the served one (has Django template tags). The repo-root `index.html` is a **stale Next.js build artifact** with no Django syntax — don't edit/reference it.
- `SECRET_KEY` is auto-generated and persisted to `blindbit/secret_key.txt` (gitignored) when the `BLINDBIT_SECRET_KEY` env var is unset. Don't commit it.
- Email uses the **console backend** — OTPs/codes (login, device removal) print to the running server's terminal, not an inbox.
- Trash retention is 30 days, fixed via `getattr(settings, 'TRASH_RETENTION_DAYS', 30)`; not in settings.py.

## Config
All behavior switches via env vars (see `blindbit/settings.py`): `BLINDBIT_SECRET_KEY`, `BLINDBIT_DEBUG`, `BLINDBIT_ALLOWED_HOSTS`, `BLINDBIT_MAX_UPLOAD_MB`, `BLINDBIT_UPLOAD_TTL_HOURS`, `BLINDBIT_RP_ID/_NAME/_ORIGIN`, `BLINDBIT_ENABLE_SSL`. Defaults already work for local dev — only override what the task needs.

## Maintenance commands
- `venv/bin/python manage.py purge_trash` — permanently delete trashed files past retention.
- `venv/bin/python manage.py purge_upload_sessions` — drop expired/abandoned chunked uploads.

## Style
UI copy is intentionally all-lowercase (buttons, labels, nav — see recent "de-capitalize" commits). Keep new UI text lowercase. Templates use Tailwind classes; badges/icons map via `vault/templatetags/vault_extras.py` (`file_icon`).