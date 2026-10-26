# BlindBit

**A zero-knowledge encrypted cloud vault built on Django.**

BlindBit stores your files as ciphertext and nothing else. Every byte of file data, every
filename, and every key is encrypted **in your browser** before it ever touches the network.
The server is a dumb, trustworthy-but-ignorant pipe: it holds encrypted blobs, wrapped keys,
and account metadata, and can never decrypt any of it. If the entire server and database were
leaked, an attacker would recover nothing but AES-GCM ciphertext and opaque wrapped keys.

> Server compromise alone reveals nothing decryptable. Crypto lives in `static/js/crypto.js`
> (Web Crypto API + a pure-JS X25519 implementation); the Django backend only stores and
> forwards opaque blobs.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [HTTPS development server](#https-development-server)
- [Configuration](#configuration)
- [Maintenance commands](#maintenance-commands)
- [Using BlindBit](#using-blindbit)
- [API reference](#api-reference)
- [Security model & limitations](#security-model--limitations)
- [Admin](#admin)
- [Docs page](#docs-page)

---

## Features

- **Zero-knowledge encryption** — files are AES-256-GCM encrypted client-side; the server
  only ever sees ciphertext, wrapped keys, and non-secret metadata.
- **Passwordless auth with WebAuthn passkeys** — sign in with a device passkey (biometrics /
  security key); a WebAuthn PRF extension derives a master-key wrapping key per device.
- **Passphrase fallback + OTP** — an optional passphrase (min. 12 chars) combined with an
  emailed one-time code as a second factor.
- **Recovery code** — a 40-entropy recovery code is the root of trust for the master key.
- **Multiple devices** — register additional passkeys per device; removal is OTP-gated.
- **Chunked uploads** — files are split into 8 MB chunks, each encrypted with a unique IV,
  uploaded via `FormData`, and reassembled server-side. Supports resumable/idempotent retries.
- **File sharing via ECDH** — share a file by re-wrapping its file key under an X25519
  ECDH-derived key for the recipient. The ciphertext itself never changes or moves.
- **Revoke & rotate** — revoke shares instantly; re-encrypt a file with a fresh key to evict
  all previous recipients.
- **Folders, favorites & search** — plaintext folder CRUD, a "Favorites" smart folder,
  starring, and client-side search/sort/filter.
- **In-browser previews** — images, video, audio, PDF, text, DOCX (mammoth), XLSX
  (SheetJS), and PPTX (JSZip + custom renderer) — all decrypted locally before rendering.
- **Trash with soft delete** — 30-day retention, restore, purge, and bulk empty.
- **Bulk actions** — multi-select to star, move, or delete files.
- **Modern admin UI** — django-unfold at `/admin/`.

---

## How it works

### The one-paragraph mental model

1. At signup you get a random **recovery code**. `MasterKey = PBKDF2(recovery code)`. This
   key never leaves your browser in plaintext.
2. Each file gets its own random **FileKey**. File bytes are AES-256-GCM encrypted **once**
   with that FileKey.
3. The FileKey itself is AES-GCM encrypted ("wrapped") under your MasterKey and stored next
   to the ciphertext.
4. Your MasterKey is stored on the server **three times wrapped**: under a
   passphrase-derived key, under a passkey-PRF-derived key, and self-wrapped as a recovery
   marker.
5. To open a file you rebuild the MasterKey (via PRF, passphrase, or recovery code), unwrap
   the FileKey, then decrypt the bytes — all in the browser.
6. To share, you re-wrap the same FileKey under an ECDH-derived key for the recipient. The
   ciphertext never changes.

There is **no double encryption of file data** — this is a two-level **envelope** scheme
(data key + key-encryption key), not nested encryption.

### Key hierarchy

```
RecoveryCode ──PBKDF2(fixed salt)──> MasterKey (AES-GCM-256)
  ├── wrap ──> FileKey_i (random per file) ──AES-GCM──> file_i bytes + filename_i
  ├── encrypt ──> X25519 private key (ECDH identity for sharing)
  ├── wrap under PassphraseKey = PBKDF2(passphrase, random salt)
  │     └──> wrapped_master_key_passphrase
  ├── wrap under PrfKey = HKDF(PRF output, prfSalt)
  │     └──> wrapped_master_key_prf
  └── self-wrap wrap(MasterKey, MasterKey)
        └──> wrapped_master_key_recovery (marker)

FileKey_i ──wrap under ECDHKey = HKDF(ECDH(eph_priv, recipient_pub))──> FileShare.wrapped_file_key
```

The MasterKey changes **only if** the recovery code changes. Rotating your passphrase or
passkey merely changes the outer wrapper — it never touches the MasterKey, any FileKey, or
any ciphertext.

### Cryptographic primitives (`static/js/crypto.js`)

| Operation | Algorithm | Details |
|---|---|---|
| File / master key | AES-256-GCM | 256-bit CSPRNG keys via Web Crypto; extractable so they can be cached in `sessionStorage` |
| Data encryption | AES-256-GCM | 96-bit IV, 128-bit auth tag (appended by WebCrypto) |
| Key wrapping | AES-GCM `wrapKey`/`unwrapKey` | 32-byte raw key → 60-byte `base64(iv ‖ wrapped)` |
| Filename | AES-256-GCM | `base64(iv ‖ ct)`; legacy files stored plain base64 and are sniffed client-side |
| Passphrase KDF | PBKDF2-SHA256 | 600,000 iterations; random 32-byte salt per user |
| Recovery KDF | PBKDF2-SHA256 | 600,000 iterations; fixed salt `"BlindBit recovery key derivation"` |
| Key agreement | X25519 | Pure-JS RFC 7748 Montgomery ladder (BigInt), no dependencies |
| Share key derivation | HKDF-SHA256 | Binds the ephemeral public key into `info` to prevent cross-pair reuse |

> **Note:** the `User` model's help text mentions Argon2id, but the implementation uses
> PBKDF2 (browsers have no native Argon2).

### Chunked upload encryption

Each 8 MB chunk gets a unique 12-byte IV built from an 8-byte random session prefix plus a
big-endian `uint32` chunk index, so IVs are never reused across chunks. The 16-byte GCM tag
is stored per chunk alongside the ciphertext, and both are reassembled into a single
authenticated ciphertext on completion.

---

## Tech stack

**Backend**

- **Python 3.12+** (bundled `venv/` runs 3.14)
- **Django 6.0** — custom `AUTH_USER_MODEL`, SQLite database
- **webauthn 3.0** — WebAuthn registration/login verification
- **django-unfold** — admin theme
- **cryptography / pyOpenSSL / Werkzeug** — TLS support for the HTTPS dev server

**Frontend**

- Vanilla JS + Django templates (Tailwind-style utility classes)
- **Web Crypto API** for all AES-GCM / PBKDF2 / HKDF operations
- Pure-JS **X25519** (no WASM, no dependencies)
- Preview renderers: mammoth (DOCX), SheetJS (XLSX), JSZip + custom PPTX renderer

No build step, no Node toolchain, no npm — the app is served entirely by Django.

---

## Project structure

```
blindbit/                     Django project package
  settings.py                 All config via BLINDBIT_* env vars
  urls.py                     / , /docs/ , /admin/ , app includes
  wsgi.py
  secret_key.txt              Auto-generated SECRET_KEY (gitignored)

accounts/                     Users, WebAuthn, passphrase, OTP, recovery, PRF
  models.py                   User (UUID PK), Device
  views.py                    registration/login/recovery/devices/keys endpoints
  urls.py                     /accounts/... + /accounts/api/...
  templates/accounts/         register, login, recovery, devices, landing

vault/                        Files, folders, chunked upload, trash
  models.py                   VaultFolder, EncryptedFile (objects vs all_objects),
                              UploadSession, FileChunk
  views.py                    dashboard, upload, folders, favorites, trash, rewrap, APIs
  urls.py                     /vault/...
  templates/vault/            dashboard, upload, trash, file_detail
  management/commands/        purge_trash, purge_upload_sessions

sharing/                      ECDH file sharing
  models.py                   FileShare (wrapped_file_key, ephemeral_public_key, revoked)
  views.py                    shared, create/revoke/delete share, re-encrypt, lookup
  urls.py                     /sharing/...
  templates/sharing/          shared, share

templates/                    Project-level templates
  base.html                   Sidebar, unlock modal, preview modal, master-key session,
                              decrypt / download / preview / reshare JS
  index.html                  Served landing page (has Django template tags)
  docs/                       /docs/ help & guide

static/
  js/crypto.js                BlindBitCrypto + BlindBitX25519 (all client-side crypto)
  js/pptx-preview.js          PPTX renderer for preview
  hero_image.png

assets/                       Design references (hero image, inspiration)

devcerts/                     Self-signed cert + key for local HTTPS
run_https.py                  HTTPS dev server (Werkzeug + TLS)
manage.py
requirements.txt
db.sqlite3                    Dev database (gitignored)
venv/                         Python virtualenv (gitignored)
```

> ⚠️ The **repo-root** `index.html` is a stale Next.js build artifact with no Django
> syntax — the served landing page is `templates/index.html`. Don't edit or reference the
> root one.

---

## Getting started

### Prerequisites

- Python 3.12 or newer
- A browser with WebAuthn + Web Crypto support (Chrome/Edge/Firefox/Safari) for full
  functionality — passkeys require a **secure context** (`https://` or `localhost`)

### 1. Clone and set up the environment

```bash
git clone <repo-url> blindbit
cd blindbit

python -m venv venv
venv/bin/pip install -r requirements.txt
```

### 2. Apply migrations

```bash
venv/bin/python manage.py migrate
```

### 3. (Optional) Create an admin user

```bash
venv/bin/python manage.py createsuperuser
```

### 4. Run the development server

```bash
venv/bin/python manage.py runserver
```

Then open **http://localhost:8000/**.

- Landing page: `/`
- Registration / login: `/accounts/register/`, `/accounts/login/`
- Vault dashboard: `/vault/dashboard/`
- Docs: `/docs/`
- Admin: `/admin/`

No environment variables need to be set for local development — the defaults already work.

> **Email is the console backend.** OTPs (login and device removal) are printed to the
> terminal running `runserver`, not delivered to an inbox. Watch that terminal for codes.

---

## HTTPS development server

WebAuthn passkeys require a secure context. `localhost` counts as one, but testing on a
LAN IP or with `BLINDBIT_ENABLE_SSL=true` (which enforces `Secure` cookies) needs real
TLS. Django's `runserver` is HTTP-only, so use the bundled Werkzeug-based server instead:

```bash
venv/bin/python run_https.py                 # https://localhost:8000
venv/bin/python run_https.py 0.0.0.0:8443    # custom host:port
```

It serves over TLS using the self-signed certificate in `devcerts/`
(`cert.pem` + `key.pem`, CN=localhost). Accept the browser's certificate warning. If you
access it from another machine, also set `BLINDBIT_RP_ID` and `BLINDBIT_RP_ORIGIN` to that
host, and regenerate the cert for the hostname/IP you use.

There is also a management command wrapper:

```bash
venv/bin/python manage.py runhttps
```

---

## Configuration

All behavior is controlled through environment variables (see `blindbit/settings.py`).
Sensible defaults are pre-set for local development — only override what you need.

| Variable | Default | Purpose |
|---|---|---|
| `BLINDBIT_SECRET_KEY` | auto-generated | Django `SECRET_KEY`. If unset, generated and persisted to `blindbit/secret_key.txt` (gitignored — **never commit it**). |
| `BLINDBIT_DEBUG` | `False` | Django debug mode. |
| `BLINDBIT_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated allowed hosts. |
| `BLINDBIT_MAX_UPLOAD_MB` | `500` | Max upload size, enforced both client- and server-side. |
| `BLINDBIT_UPLOAD_TTL_HOURS` | `24` | Lifetime of a pending chunked-upload session before it expires. |
| `BLINDBIT_RP_ID` | `localhost` | WebAuthn relying-party ID (the effective domain). |
| `BLINDBIT_RP_NAME` | `BlindBit` | WebAuthn relying-party display name. |
| `BLINDBIT_RP_ORIGIN` | `http://localhost:8000` | WebAuthn expected origin (must match the URL you browse to). |
| `BLINDBIT_ENABLE_SSL` | `False` | When `true`, enables `SECURE_SSL_REDIRECT`, `Secure` cookies, HSTS, and proxy header handling. |

Other fixed settings:

- **Chunk size:** 8 MB (`CHUNK_SIZE = 8388608`)
- **Trash retention:** 30 days (`getattr(settings, 'TRASH_RETENTION_DAYS', 30)`)
- **Time zone:** `Asia/Kolkata`
- **Database:** SQLite at `db.sqlite3`

---

## Maintenance commands

```bash
# Permanently delete trashed files past the 30-day retention window
venv/bin/python manage.py purge_trash

# Drop expired / abandoned chunked upload sessions and their chunks
venv/bin/python manage.py purge_upload_sessions
```

Neither runs on a schedule — invoke them manually (e.g. from cron) as needed.

---

## Using BlindBit

### Registration

1. Go to `/accounts/register/` and enter a username and email.
2. Your browser creates a **passkey** (WebAuthn). If the authenticator supports the PRF
   extension, a per-user PRF salt is registered so the master key can be derived on login.
3. The browser generates a **recovery code** and derives your **MasterKey** from it
   (PBKDF2). The recovery code is shown once — copy or download it. **It cannot be
   recovered if lost.**
4. An X25519 identity keypair is generated; the private key is sealed under your MasterKey.
5. If you set a passphrase (≥ 12 chars), the MasterKey is additionally wrapped under a
   passphrase-derived key.

The server verifies the attestation, stores the wrapped keys, and signs you in. It never
sees your recovery code, passphrase, master key, or X25519 private key.

### Logging in

- **Passkey (primary):** authenticate with your device; the PRF output unwraps your
  MasterKey automatically.
- **Passphrase (fallback):** enter your passphrase — it's derived and unwrapped locally —
  then confirm with a 6-digit OTP sent by email (printed to the server console in dev).
  The passphrase alone never logs you in; the OTP is always required.
- **Recovery:** use your recovery code together with the original device's passkey.

### Uploading

Files are encrypted entirely in the browser before upload:

1. A fresh random **FileKey** is generated per file; the filename is encrypted with it.
2. The FileKey is wrapped under your MasterKey.
3. The file is sliced into 8 MB chunks, each encrypted with a unique IV, and streamed to
   the server via `upload_start` → `upload_chunk` (×N, with retries) → `upload_complete`.
4. The server assembles the chunks and creates the `EncryptedFile` record.

### Sharing

1. Look up the recipient by username — they must already have an X25519 public key.
2. The browser generates an ephemeral X25519 keypair, performs ECDH with the recipient's
   public key, derives a wrapping key via HKDF, and re-wraps the **FileKey**.
3. Only the wrapped FileKey and the ephemeral public key are sent to the server.
4. The recipient's browser reverses the ECDH to unwrap the FileKey and decrypt the same
   ciphertext. The file bytes are never re-uploaded or re-encrypted.

Revoking a share flips a flag; re-encrypting a file generates a brand-new FileKey and new
ciphertext, permanently evicting every prior recipient (they must be re-shared explicitly).

### Trash

Deleting a file soft-deletes it (sets `deleted_at`) and revokes its active shares. The
trash view lists, restores, or permanently purges files; `empty_trash` clears everything.
Retention is enforced by the `purge_trash` command.

---

## API reference

All endpoints return JSON unless noted. All are CSRF-protected Django views requiring an
authenticated session.

### Accounts — `/accounts/api/...`

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `registration-options/` | WebAuthn creation options (challenge, PRF salt) |
| POST | `register-begin/` | Verify attestation, create user + device, log in |
| POST | `login-begin/` | WebAuthn request options + wrapped keys for the user |
| POST | `login-complete/` | Verify assertion, log in |
| POST | `login-send-otp/` | Email a 6-digit OTP (console backend in dev) |
| POST | `login-passphrase/` | Verify passphrase verifier + OTP, log in |
| POST | `confirm-recovery/` | Mark recovery code confirmed / onboarding done |
| GET/POST | `my-keys/` | Read or update the user's wrapped keys |
| POST | `keys-setup/` | One-time master-key setup / rotation (wraps recovery, passphrase, X25519) |
| POST | `prf-upgrade-options/` | Options to add PRF to a pre-PRF account |
| POST | `enable-prf/` | Store the PRF-wrapped master key |
| POST | `device/add-options/` | WebAuthn options to add a new device passkey |
| POST | `device/add-complete/` | Verify and store the new device credential |
| POST | `device/<id>/send-otp/` | Send OTP required to remove a device |
| POST | `device/<id>/verify-remove/` | Verify OTP and remove the device |

### Vault — `/vault/...`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `dashboard/`, `folder/<id>/` | Dashboard / folder view |
| POST | `api/folders/create/`, `api/folders/<id>/rename/`, `api/folders/<id>/delete/` | Folder CRUD |
| POST | `api/uploads/start/` | Begin a chunked upload → returns a session `token` |
| POST | `api/uploads/chunk/` | Upload one encrypted chunk (`FormData`, idempotent by index) |
| POST | `api/uploads/complete/` | Assemble chunks into an `EncryptedFile` |
| POST | `api/uploads/cancel/` | Abort a session (cascades chunks) |
| POST | `api/upload/` | Legacy single-request upload (`FormData`) |
| GET | `api/files/<id>/download-data/` | Ciphertext + wrapped key + IV/tag metadata (owner or share) |
| GET | `file/<id>/download/` | Binary download with `X-*` headers |
| POST | `api/files/<id>/rewrap-key/` | Re-wrap a file key under a new MasterKey |
| POST | `api/files/<id>/favorite/` | Toggle star |
| POST | `api/files/bulk-favorite/`, `bulk-move/`, `bulk-delete/` | Bulk actions on `file_ids[]` |
| POST | `file/<id>/move/`, `file/<id>/delete/` | Move / soft-delete |
| GET | `trash/` | Trash view (lists soft-deleted files) |
| POST | `file/<id>/restore/`, `file/<id>/purge/`, `api/trash/empty/` | Restore, permanently delete, or empty trash |
| GET | `api/files/` | File list JSON |

### Sharing — `/sharing/...`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `api/lookup-user/?q=<username>` | Find a recipient and their X25519 public key |
| POST | `api/create/` | Store an ECDH-wrapped FileKey for a recipient |
| POST | `api/revoke/<id>/`, `api/delete/<id>/` | Revoke or delete a share |
| POST | `api/re-encrypt/` | Replace ciphertext + wrapped key (rotate & evict) |
| GET | `api/shared-files/` | Files shared with the current user |

---

## Security model & limitations

### What the server can see

A full server/database compromise yields only: AES-GCM ciphertext, wrapped (encrypted)
keys, a SHA-256 passphrase verifier, and the metadata below. None of it is decryptable
without secrets that exist only in the user's browser.

**Plaintext metadata that IS visible to the server:** folder names, MIME types, file sizes
(`original_size` / ciphertext length), the share graph (who shared what with whom),
timestamps, and device names.

### Known limitations — read before deploying

- **The recovery code is the root of trust.** Lose the recovery code, passphrase, PRF
  device, and active session all at once and the data is **unrecoverable by design**.
- **Recovery login still requires the original device's passkey** — the code alone does
  not log you in. A wrong recovery code is not rejected server-side; the derived key simply
  fails to decrypt.
- **`passphrase_verifier = SHA256(wrapped_master_key_passphrase)` is not a password
  hash.** It proves you could unwrap the key, but the OTP second factor is still required.
- **Client trust:** zero-knowledge holds only if the browser is uncompromised and TLS is
  intact. Serve over HTTPS in production (`BLINDBIT_ENABLE_SSL=true` + a real cert).
- **Email is the console backend** — OTPs appear in server logs. Fine for development, not
  for production; plug in a real SMTP backend before going live.
- **Memory:** decryption needs roughly the file's size in RAM (Blob + preview), and the
  upload cap defaults to 500 MB.
- **Keep `blindbit/secret_key.txt` out of version control**, and set `BLINDBIT_DEBUG` /
  `BLINDBIT_ALLOWED_HOSTS` correctly in production.
- **No automated tests, linter config, or CI exist** in this repository.
- **Master-key rotation after onboarding is not exposed in the UI.** The one-time
  vault-setup panel appears only during onboarding; rotating the recovery code later would
  orphan existing wrapped file keys if the old MasterKey isn't available.

### Proving single-encryption to an auditor

1. Open `vault/templates/vault/upload.html` — one `encrypt` call per chunk with the
   FileKey. No nested encryption.
2. Open `static/js/crypto.js` `wrapKey` — the second operation only ever touches a 32-byte
   key (input 32 bytes, output 60 bytes). File bytes never pass through it.
3. Capture an `upload_start` payload — `wrapped_file_key` is ~80 characters regardless of
   file size (key-sized, not file-sized).
4. Rotate the passphrase — the `ciphertext` column in `vault_encryptedfile` is unchanged;
   only the `wrapped_*` columns update.
5. Flip one byte of `ciphertext` — the GCM tag check fails on decrypt, proving a single
   authenticated layer.

---

## Admin

The admin UI (django-unfold) lives at **`/admin/`** and is organized into:

- **Content** → Encrypted Files
- **Sharing** → File Shares
- **Users & Auth** → Users, Devices, Groups

Create an account with `venv/bin/python manage.py createsuperuser`.

> Remember: admin users can see ciphertext and wrapped keys, but **cannot decrypt them** —
> that's the point.

---

## Docs page

An end-user help guide is served at **`/docs/`** (`templates/docs/`). It covers account
setup, uploading, sharing, and recovery for non-technical users.

---

## License

No license file is present in this repository. Add one before distributing.
