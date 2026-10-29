# BlindBit — Detailed Project Explanation

> Zero-knowledge encrypted cloud vault. Django 6 server stores only ciphertext
> and wrapped keys. All file/master-key crypto runs in the browser via Web Crypto
> + pure-JS X25519. Server compromise alone reveals nothing decryptable.

---

## 0. One-paragraph mental model

1. At signup you get a random **recovery code**. `MasterKey = PBKDF2(code)`. This key never leaves your browser in plaintext.
2. Each file gets its own random **FileKey**. File bytes are AES-256-GCM encrypted **once** with that FileKey.
3. The FileKey itself is AES-GCM encrypted (wrapped) under your MasterKey and stored next to the ciphertext.
4. Your MasterKey itself is stored on the server **3x wrapped**: under passphrase-derived key, under passkey-PRF-derived key, and self-wrapped as recovery marker.
5. To open a file you rebuild MasterKey (PRF or passphrase or recovery code), unwrap FileKey, decrypt bytes — all in `templates/base.html` + `static/js/crypto.js`.
6. To share you re-wrap the same FileKey under an ECDH-derived key for the recipient. Ciphertext never changes.

There is **no double encryption of file data**. There is **two-level envelope**: data-key + key-encryption-key.

---

## 1. Repository layout and runtime

```
blindbit/               Django project (settings.py, urls.py, wsgi)
accounts/               User, Device, WebAuthn, passphrase, OTP, recovery, PRF
  models.py             User(UUID), Device
  views.py              registration_options, register_complete, login_begin/complete,
                        login_passphrase, login_send_otp, confirm_recovery, my_keys,
                        keys_setup, prf_upgrade, add_device_*, send/remove OTP
  urls.py               /accounts/... + /accounts/api/...
  templates/accounts/   register.html, login.html, recovery.html, devices.html, landing.html
vault/                  files, folders, chunked upload, trash
  models.py             VaultFolder, EncryptedFile (objects vs all_objects), UploadSession, FileChunk
  views.py              dashboard, upload_view, create/rename/delete/move folder,
                        upload_file (legacy), start_upload/upload_chunk/complete_upload/cancel,
                        download_file/download_file_data, file_detail, delete/restore/purge/empty_trash,
                        rewrap_file_key, file_list_api
  templates/vault/      dashboard.html (files+folders+upload modal+restore panel), upload.html, trash.html
sharing/                sharing
  models.py             FileShare(file, owner, recipient, wrapped_file_key, ephemeral_public_key, nonce, revoked)
  views.py              shared, share_view, create_share, revoke/delete, re_encrypt_and_reshare, lookup_user, APIs
  templates/sharing/    shared.html, share.html
static/js/crypto.js     BlindBitCrypto (AES-GCM, PBKDF2, wrap/unwrap, filename, b64) + BlindBitX25519 (pure BigInt)
static/js/pptx-preview.js  PPTX renderer for preview
templates/base.html     sidebar, unlock modal, preview modal, master-key session, decrypt/download/preview/reshare JS
templates/index.html    served landing (has Django tags). Repo-root index.html is stale Next.js artifact — ignore.
templates/docs/         help/guide
venv/                   Python 3.12 env. Run `venv/bin/python manage.py runserver`, `migrate`, `createsuperuser`.
db.sqlite3              dev DB. Tables `accounts_user`, `accounts_device`, `vault_encryptedfile`, etc.
blindbit/secret_key.txt auto-generated SECRET_KEY if BLINDBIT_SECRET_KEY unset (gitignored, never commit).
```

Config: all via env `BLINDBIT_SECRET_KEY, BLINDBIT_DEBUG, BLINDBIT_ALLOWED_HOSTS, BLINDBIT_MAX_UPLOAD_MB (default 500), BLINDBIT_UPLOAD_TTL_HOURS (default 24), BLINDBIT_RP_ID/_NAME/_ORIGIN, BLINDBIT_ENABLE_SSL`. See `blindbit/settings.py` and `AGENTS.md`.
Email: console backend — OTPs print to server terminal, not inbox.
Trash retention: 30 days via `getattr(settings,'TRASH_RETENTION_DAYS',30)`.
Chunk size: 8 MB (`8388608`, `UPLOAD_CHUNK_SIZE` in `upload.html` + `dashboard.html`, `chunk_size` in `UploadSession`).
Admin: `django-unfold` at `/admin/`.
Commands: `purge_trash`, `purge_upload_sessions`. No test/lint/CI.

---

## 2. Cryptography primitives (`static/js/crypto.js`)

All extractable AES-GCM-256 keys (`true, ['encrypt','decrypt','wrapKey','unwrapKey']`) so they can be exported to `sessionStorage`.

### 2.1 `generateMasterKey`, `generateFileKey` (`crypto.js:6-21`)

```js
crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt','decrypt','wrapKey','unwrapKey'])
```

CSPRNG 256-bit. FileKey uses this directly per file. MasterKey in practice is **derived**, not generated (see §3), but helper exists.

### 2.2 `encrypt(key, plaintext)` / `decrypt(key, ciphertext, iv)` (`crypto.js:24-37`)

```js
iv = getRandomValues(12B)
ciphertext+tag = subtle.encrypt({name:'AES-GCM', iv}, key, plaintext) // tag appended (16B) by WebCrypto
decrypt = subtle.decrypt({name:'AES-GCM', iv}, key, ciphertext+tag)
```

AES-256-GCM, 96-bit IV, 128-bit tag. Failure throws `Decryption failed`.

### 2.3 `wrapKey(wrappingKey, keyToWrap)` / `unwrapKey` (`crypto.js:40-56`)

```js
iv = random(12B)
wrapped = subtle.wrapKey('raw', keyToWrap, wrappingKey, {name:'AES-GCM', iv}) // raw 32B -> encrypted + tag
stored = base64(iv || wrapped) // 12 + 32 + 16 = 60B -> 80 chars b64
unwrap: split iv/wrapped, subtle.unwrapKey('raw', wrapped, wrappingKey, {AES-GCM,iv}, {AES-GCM,256}, true, ['encrypt','decrypt'])
```

This is **key encryption**, not second data encryption. Same primitive re-used for FileKey, MasterKey, X25519 flows.

### 2.4 Filename (`crypto.js:59-80`)

```js
encryptFilename(key, name) = base64(iv(12B) || AES-GCM(key, iv, UTF8(name)))
decryptFilename(key, b64) = UTF8(decrypt) or null if legacy plain-b64 or tampered
```

Legacy files stored `base64(UTF8(name))` without encryption; `base.html:816-835 blindBitOwnFileName` sniffs printable ASCII to support both.

### 2.5 Passphrase KDF (`crypto.js:84-94`)

```js
keyMaterial = importKey('raw', UTF8(passphrase), 'PBKDF2', false, ['deriveKey'])
key = deriveKey({name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'}, keyMaterial, {name:'AES-GCM',length:256}, true, [...])
```

600k iterations, SHA-256. Salt: fixed `UTF8("BlindBit recovery key derivation")` for MasterKey; random 32B per user for passphrase wrap key (`register.html:471`). Salt hex stored as `passphrase_salt`.

Note model help text says Argon2id but code is PBKDF2 (browser has no Argon2).

### 2.6 Utilities (`crypto.js:96-136`)

`randomHex`, `generateRecoveryCode` (8 groups x5 from `A-Z2-9`, 40B entropy), `bufferToBase64`, `base64ToBuffer`, `encryptToB64(bytes)=base64(iv||ct)` / `decryptFromB64` (used for X25519 private).

### 2.7 X25519 pure-JS (`crypto.js:139-247`)

RFC 7748 Montgomery ladder with BigInt, `P=2^255-19`, `A24=121665`, clamping `k[0]&=248, k[31]&=127|=64`.

* `generateKeypair()`: `scalar=random(32B)`, `pub=scalarmult(scalar, basepoint=9)`, both hex 64 chars.
* `ecdh(privHex, pubHex) = scalarmult(priv, pub)` 32 raw bytes.
* `deriveWrappingKey(secret, ephemeralPubHex)`: `HKDF-SHA256(salt=UTF8("BlindBit X25519 HKDF"), ikm=secret, info=UTF8("BlindBit share v1:"+ephemeralPubHex)) -> AES-GCM-256` with `wrapKey/unwrapKey` usages. Binding ephemeral pub prevents cross-pair reuse.
* PRF variant: `HKDF(salt=prfSalt, info="BlindBit PRF wrapping key v1")` — `register.html:295-304`, `login.html:278-287`.

No server X25519 code; `accounts.models` only stores hex public + sealed private.

---

## 3. Key hierarchy — formulas

```
RecoveryCode ──PBKDF2(fixed salt)──> MasterKey (AES-GCM-256, stable until code rotates)
  |--wrap──> FileKey_i (random per file) ──AES-GCM──> file_i bytes + filename_i
  |--encrypt──> X25519_priv (ECDH identity)
  |--wrap under PassphraseKey=PBKDF2(passphrase, random salt) ──> wrapped_master_key_passphrase
  |--wrap under PrfKey=HKDF(PRF_output, prfSalt) ──> wrapped_master_key_prf
  └--self-wrap wrap(MasterKey,MasterKey) ──> wrapped_master_key_recovery (marker)
FileKey_i ──wrap under ECDHKey=HKDF(ECDH(eph_priv, recip_pub))──> FileShare.wrapped_file_key
```

MasterKey changes **iff** recovery code changes. Passphrase/passkey rotation only changes the outer wrapper, never MasterKey or FileKeys or ciphertext.

---

## 4. Storage — tables and columns

### 4.1 `accounts_user` (model `accounts/models.py:5`)

`id UUID PK, username, email (unique), password (unused — WebAuthn/OTP used), display_name, x25519_public_key (hex plaintext), encrypted_x25519_private_key (base64(iv||ct) under MasterKey), wrapped_master_key_prf (b64), prf_salt (hex), wrapped_master_key_passphrase (b64), wrapped_master_key_recovery (b64 self-wrap), recovery_phrase_confirmed bool, passphrase_enabled bool, passphrase_salt (hex), passphrase_verifier = SHA256(wrapped_master_key_passphrase) hex, is_onboarded bool`.

No plaintext MasterKey, passphrase, recovery code, or FileKey.

### 4.2 `accounts_device` (`accounts/models.py:27`)

`id UUID, user FK, name, credential_id (b64url), public_key (b64url), prf_enabled bool, wrapped_master_key (legacy per-device, mostly empty now), created_at, last_used`.

### 4.3 `vault_vaultfolder` (`vault/models.py:10`)

`id UUID, owner FK, name (plaintext — visible to you only, not encrypted), created_at, is_favorites bool`.

### 4.4 `vault_encryptedfile` (`vault/models.py:23`)

`id UUID, owner FK, folder FK nullable SET_NULL, ciphertext Binary (concatenated per-chunk raw ct, tags stripped, see §7), wrapped_file_key (b64 iv||wrapped or legacy raw 32B b64), encrypted_filename (b64 iv||ct), encrypted_metadata (mostly '' for chunked, legacy JSON), nonce (b64 8B prefix for chunked or 12B IV for legacy), auth_tag (JSON {segments:[{iv,tag,size}]} for chunked or b64 tag for legacy), original_size int, mime_type, uploaded_at/updated_at/last_opened_at, is_favorite bool, deleted_at nullable (trash)`.

Managers: `objects` filters `deleted_at__isnull=True`; `all_objects` includes trash. All trash/restore/purge must use `all_objects`.

### 4.5 `vault_uploadsession` + `vault_filechunk` (`vault/models.py:50-84`)

`UploadSession(id, owner, folder, token=urlsafe32 unique, encrypted_filename, wrapped_file_key, nonce=8B prefix b64, mime, original_size, chunk_size, total_chunks, chunks_received, created_at, expires_at)`.
`FileChunk(id, session FK CASCADE, index, ciphertext Binary (raw ct without tag), nonce=12B IV b64, auth_tag=16B tag b64, unique(session,index))`.

### 4.6 `sharing_fileshare` (`sharing/models.py:5`)

`id UUID, file FK CASCADE, owner FK, recipient FK, wrapped_file_key (ECDH-wrapped b64), ephemeral_public_key (hex), nonce ('' unused), revoked bool, created_at/updated_at, unique(file,recipient)`.

---

## 5. Client key session (`templates/base.html:359-486`)

```js
blindBitKeyName(user) = 'blindbit_master_key_raw_'+user
blindBitSaveMasterKey(rawB64, user) -> sessionStorage.setItem(...)
blindBitLoadMasterKey(user) -> sessionStorage (+ legacy 'blindbit_master_key_raw' fallback)
blindBitKeyRestorePromise: on page load, delete any localStorage copies, import sessionStorage raw -> window.BlindBitMasterKey
blindBitEnsureMasterKey(): return memory, else await restore promise, else re-import sessionStorage, else show #unlock-modal -> POST login_begin -> PBKDF2(pass,salt)->unwrap -> cache -> resolve
```

Unlock modal (`base.html:187-209,396-486`): passphrase input, fetches `wrapped_master_key_passphrase + passphrase_salt` for `{{user.username}}`, derives, unwraps, exports raw to sessionStorage. Never throws — returns null on cancel; callers abort with `Master key required`.

---

## 6. Registration deep dive (`accounts/templates/accounts/register.html`, `accounts/views.py:100-208`)

1. Enter username/email -> `POST registration-options` -> WebAuthn `PublicKeyCredentialCreationOptions` (challenge, user.id).
2. JS generates `prfSalt=random(32B)`, sets `extensions.prf.eval.first=b64url(prfSalt)`, `navigator.credentials.create`. Captures `prfOutput` from `getClientExtensionResults().prf.results.first` if supported.
3. `recoveryCode=generateRecoveryCode()`, `MasterKey=deriveKeyFromPassphrase(code, "BlindBit recovery key derivation")`, export raw -> `blindBitSaveMasterKey` + `window.BlindBitMasterKey`.
4. `X25519.generateKeypair()`, `encryptedX25519Priv=encryptToB64(MasterKey, privBytes)`.
5. Build payload: username/email/display_name/credential/device_name + `x25519_public_key`, `encrypted_x25519_private_key`, `passphrase_enabled/salt/wrapped (if passphrase >=12 chars)`, `prf_enabled/salt/wrapped (if prfOutput)`, `wrapped_master_key_recovery=wrapKey(MasterKey,MasterKey)`.
6. `POST register-begin` verifies attestation (`verify_registration_response` with RP_ID/ORIGIN), `SHA256(wrapped)` as `passphrase_verifier`, `User.objects.create_user(...)` + `Device.objects.create(...)`, `login()`.
7. `POST confirm-recovery` sets `recovery_phrase_confirmed/is_onboarded`. Show recovery card (copy/download `.txt`).

Server never sees code, passphrase, MasterKey, or X25519 private.

---

## 7. Login deep dive (`accounts/templates/accounts/login.html`, `accounts/views.py:211-400`)

### 7.1 Passkey + PRF (`login.html:307-439`)

`POST login_begin {username}` -> `{allowCredentials, challenge, prf_enabled/salt/wrapped, has_passphrase}`. If PRF available, set `extensions.prf.eval.first=b64url(prfSalt)`. `navigator.credentials.get` -> `POST login_complete {credential}` verifies signature, `login()`, updates `last_used`. In parallel, `derivePrfWrappingKey(salt, prfOutput) -> unwrap(wrapped_master_key_prf) -> MasterKey -> sessionStorage`. Failures fall back to unlock modal. Wrong-device errors mapped (`NotAllowedError`, etc.).

### 7.2 Passphrase + OTP (`login.html:445-562`)

1. `POST login_begin` -> get `wrapped + salt`. `PBKDF2(pass,salt)->unwrap` locally. On failure `Invalid passphrase`. On success cache MasterKey + compute `verifier=SHA256(wrapped)`.
2. `POST login_send_otp` emails (console) 6-digit code.
3. `POST login_passphrase {username, passphrase_verifier, otp, device_name}` checks verifier matches stored `SHA256(wrapped)` + OTP, `login()`.

Passphrase alone never logs in; OTP second factor required. MasterKey already cached before OTP so dashboard opens unlocked.

### 7.3 Recovery (`accounts/templates/accounts/recovery.html:43-122`)

Enter username + `XXXXX-...` (regex validated). Derive `recoveryKey=PBKDF2(code, fixed salt)` (= MasterKey if code correct; **not verified against server** — wrong code still logs in via passkey but files fail). `POST login_begin` -> `navigator.credentials.get` -> `POST login_complete` -> on ok export/cache MasterKey -> dashboard. Requires original-device passkey; otherwise `Recovery requires the original device passkey`. No rotation, no server write.

---

## 8. Upload — chunked flow in detail

Single-file example 20 MB -> `totalChunks=ceil(20/8)=3`.

`vault/templates/vault/upload.html:177-244` (dashboard modal duplicates same logic `dashboard.html:1095-1250`):

```js
fileKey = generateKey(AES-GCM-256) // per file, extractable for wrap
wrappedFileKey = BlindBitMasterKey ? wrapKey(MasterKey,fileKey) : b64(raw fileKey) // legacy fallback
prefix = random(8B)
POST upload_start {encrypted_filename=encryptFilename(fileKey,name), wrapped_file_key, nonce=b64(prefix), mime, original_size, chunk_size:8388608, total_chunks, folder_id}
-> {token}
for i in 0..total-1:
  iv = prefix(8B) || uint32BE(i) // makeChunkIv, 12B unique per chunk, no reuse
  pt = file.slice(i*8M, min(...)).arrayBuffer()
  ct+tag = encrypt(iv, fileKey, pt) // WebCrypto appends 16B tag
  ciphertext=ct[:-16], tag=ct[-16:]
  POST upload_chunk FormData{token,index,ciphertext Blob,nonce=b64(iv),auth_tag=b64(tag)} with 3x retry
POST upload_complete {token} -> {file_id} or {missing:[...]} 409
```

Server (`vault/views.py:211-333`): validates size vs `MAX_UPLOAD_SIZE_MB`, folder ownership (never Favorites), `UploadSession(token=urlsafe32, expires=now+TTL)`. `upload_chunk` validates index range + `size<=chunk_size+16`, `update_or_create(session,index)` (idempotent retry), increments `chunks_received` only on create. `complete_upload` checks `len(chunks)==total`, `sum(len)==original_size`, builds `ciphertext=b''.join`, `segments=[{iv,tag,size}]`, creates `EncryptedFile(..., nonce=prefix, auth_tag=json segments)`, deletes session. `cancel_upload` drops session+chunks (CASCADE).

Filename/MIME/folder/wrapped key travel in `start`, never file bytes in JSON (FormData binary for chunks).

---

## 9. Download / preview / filename resolve (`templates/base.html:488-836`, `vault/views.py:335-389`)

`GET /vault/api/files/<id>/download-data/`:

* Owner hit: `EncryptedFile(owner=user)` -> `{access:'owner', ciphertext:b64(raw), wrapped_file_key, nonce, auth_tag, mime, encrypted_filename, original_size}` + touches `last_opened_at`.
* Else share hit: `FileShare(recipient=user, revoked=False)` -> `{access:'shared', ciphertext:b64(file.ciphertext), wrapped_file_key:share.wrapped, ephemeral_public_key, nonce:file.nonce, auth_tag:file.auth_tag, ...}`.
* Else 404. `_get_accessible_file` variant for raw `download_file` adds same as `X-*` headers.

Client:

```js
fileKey = blindBitFileKey(data) // owner: raw32? import : unwrap(MasterKey); shared: decrypt X25519priv with MasterKey -> ECDH -> HKDF -> unwrap
name = decryptFilename(fileKey, encrypted_filename) ?? base64-decode legacy
bytes = blindBitDecryptData(fileKey, data) // if auth_tag JSON: per-segment tagged=ct+tag, decrypt(iv) concat; else single decrypt(nonce)
Blob(bytes, mime) -> objectURL -> <a download> or preview renderer (image/video/audio/pdf/iframe, text/pre, docx via mammoth, xlsx via SheetJS, pptx via JSZip+preview)
```

List-page names resolved eagerly without downloading bytes (`blindBitOwnFileName`, `blindBitSharedFileName`, `dashboard.html:942-970`).

---

## 10. Sharing deep dive

Create (`base.html:304-353 blindBitReshare`, `sharing/views.py:24-63`):

```js
recipient = lookup-user?q=username -> must have x25519_public_key
fileKey = raw32? import : unwrap(MasterKey, file.wrapped) // owner must unlock
eph = generateKeypair(); secret = ecdh(eph.priv, recipient.pub); wrapKey = deriveWrappingKey(secret, eph.pub)
wrapped = wrapKey(wrapKey, fileKey)
POST /sharing/api/create/ {file_id, recipient, wrapped_file_key:wrapped, ephemeral_public_key:eph.pub}
```

Server checks self-share, recipient keys, `get_or_create(file,recipient)` (revived if revoked). No crypto on server.

Consume: §9 shared branch. Filename needs same ECDH chain (`blindBitSharedFileName`).

Revoke/delete (`views.py:67-78`): `revoked=True` or row delete. Bulk delete/trash auto-revokes (`vault/views.py:169,405`).
Evict + rotate: `re_encrypt_and_reshare` (`sharing/views.py:82-98`) takes `new_ciphertext_hex/nonce/tag/wrapped` from browser (browser already generated new FileKey + re-encrypted), overwrites `EncryptedFile`, deletes active shares. Recipients must be re-added manually.

---

## 11. Folders / search / bulk / trash

* Folders plaintext CRUD (`views.py:76-103`), grid/list toggle + sort/search/filter purely client (`dashboard.html:668-738`). Move validates not-Favorites (`views.py:107-118,146-157`).
* Star toggles `is_favorite`, auto-creates `Favorites(is_favorites=True)` (`views.py:122-142`). Bulk star/move/delete via `file_ids[]` (`views.py:133-170`).
* Trash: `delete_file` soft + revoke shares (`views.py:402-406`), `trash_view` lists `all_objects deleted`, `restore` clears, `purge/empty` hard deletes (`views.py:409-438`). Retention display only; enforcement in `purge_trash` command.

---

## 12. Vault setup / re-wrap (the only post-signup key rotation)

Panel shows iff `not wrapped_master_key_recovery or not encrypted_x25519_private_key` (`dashboard.html:47`).

`dashboard.html:1003-1092`:

```js
oldMk = window.BlindBitMasterKey // may be null
newMaster = PBKDF2(newRecoveryCode, fixed salt); cache it
payload = {wrapped_recovery=wrap(newMaster,newMaster), wrapped_passphrase?, new X25519 pair sealed}
POST keys-setup // accounts/views.py:573-604 overwrites user row
if (oldMk) for each .file-row with non-32B key: fileKey=unwrap(oldMk) -> newWrapped=wrap(newMaster) -> POST rewrap-key // vault/views.py:442-452
```

Consequences: with `oldMk` files stay open (same FileKey, new wrapper). Without it old `wrapped_file_key`s are orphaned (data loss) and new X25519 private breaks incoming shares. Legacy raw-32B files skip rewrap and survive. No UI exists to rotate after onboarding — to forbid rotation entirely remove this panel + `keys-setup`.

---

## 13. Security properties and limits

Guarantees: server/DB leak yields only AES-GCM ciphertext + wrapped keys + password verifier hash; filenames/MIME sizes (sizes leak via `original_size`/ciphertext length) except size/MIME/folder structure still visible. Zero-knowledge holds iff browser is trusted and TLS intact (`BLINDBIT_ENABLE_SSL`, `run_https.py` + `devcerts/` for local HTTPS).

Limits / gotchas to know:

* Recovery code is the root of trust. Lose code + passphrase + PRF device + session = unrecoverable by design.
* Recovery login still needs original passkey device; code alone does not log in. Wrong code is not rejected (derived key just fails to decrypt).
* `passphrase_verifier = SHA256(wrapped)` is not a password hash; it proves you could unwrap, but OTP is still required.
* Folder names, MIME types, sizes, share graph, timestamps are plaintext metadata.
* 500 MB cap is enforced client + server (`MAX_UPLOAD_SIZE_MB`); decrypt needs ~file size in RAM for Blob + preview.
* Console email means OTPs appear in server logs — fine for dev, not prod.
* `SECRET_KEY` persistence file must stay uncommitted; `BLINDBIT_DEBUG`/`ALLOWED_HOSTS` must be set correctly in prod.

---

## 14. API catalog (JSON unless noted)

Accounts: `POST registration-options`, `POST register-begin`, `POST login-begin -> {has_passphrase, wrapped_*, prf_*, allowCredentials, challenge}`, `POST login-complete`, `POST login-send-otp`, `POST login-passphrase`, `POST confirm-recovery`, `GET/POST my-keys`, `POST keys-setup`, `POST prf-upgrade-options/enable-prf`, `POST device/add-options/add-complete`, `POST device/<id>/send-otp/verify-remove`.
Vault: `POST create_folder/rename_folder/delete_folder/move_file/toggle_favorite/bulk_*`, `POST upload (legacy FormData)`, `POST upload_start (JSON)`, `POST upload_chunk (FormData)`, `POST upload_complete/cancel (JSON)`, `GET files/<id>/download-data/`, `GET files/<id>/download/ (binary+X-headers)`, `POST files/<id>/rewrap-key`, `GET file_list_api`.
Sharing: `GET shared/api/lookup-user?q=`, `POST sharing/api/create/`, `POST share/<id>/revoke|delete`, `POST re_encrypt_and_reshare`, `GET shared_files_api`.

---

## 15. How to prove single-encryption to an auditor

1. Open `upload.html:219` — one `encrypt` per chunk with FileKey. No nested encrypt.
2. Open `crypto.js:40-48` — second op is `wrapKey` on 32B key, input length 32, output 60B. Log lengths to show file bytes never pass through it.
3. Capture `upload_start` payload — `wrapped_file_key` is ~80 chars regardless of file size (key-sized, not file-sized).
4. Rotate passphrase via `keys-setup` — `ciphertext` column in `vault_encryptedfile` unchanged (`sqlite3`/admin), only `wrapped_*` change.
5. Corrupt one byte of `ciphertext` — GCM tag fails in `blindBitDecryptData`, proving authenticated single layer.

