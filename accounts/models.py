import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=100, blank=True)
    x25519_public_key = models.TextField(blank=True, help_text="Hex-encoded X25519 public key for sharing ECDH")
    encrypted_x25519_private_key = models.TextField(blank=True, help_text="X25519 private key wrapped under the Master Key")
    wrapped_master_key_prf = models.TextField(blank=True, help_text="Master Key wrapped under PRF-derived key")
    prf_salt = models.TextField(blank=True, help_text="Random salt (hex) for WebAuthn PRF key derivation")
    wrapped_master_key_passphrase = models.TextField(blank=True, help_text="Master Key wrapped under Argon2id-derived passphrase key")
    wrapped_master_key_recovery = models.TextField(blank=True, help_text="Master Key wrapped under recovery phrase key")
    recovery_phrase_confirmed = models.BooleanField(default=False)
    passphrase_enabled = models.BooleanField(default=False, help_text="True if user uses passphrase fallback")
    passphrase_salt = models.TextField(blank=True, help_text="PBKDF2 salt for passphrase key derivation (hex)")
    passphrase_verifier = models.TextField(blank=True, help_text="SHA256(wrapped_master_key_passphrase) for passphrase login verification")
    is_onboarded = models.BooleanField(default=False)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    name = models.CharField(max_length=200)
    credential_id = models.TextField(blank=True, help_text="WebAuthn credential ID (base64url)")
    public_key = models.TextField(blank=True, help_text="WebAuthn credential public key (base64url)")
    prf_enabled = models.BooleanField(default=False)
    wrapped_master_key = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_used']

    def __str__(self):
        return f"{self.name} ({self.user.username})"
