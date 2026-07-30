import uuid
from django.db import models
from django.conf import settings

class FileShare(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey('vault.EncryptedFile', on_delete=models.CASCADE, related_name='shares')
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shares_sent')
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shares_received')
    wrapped_file_key = models.TextField(help_text="File Key wrapped via ECDH for recipient")
    ephemeral_public_key = models.TextField(help_text="Ephemeral X25519 public key used in ECDH")
    nonce = models.TextField(blank=True, help_text="Nonce used in wrapping")
    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = ['file', 'recipient']

    def __str__(self):
        return f"Share {self.file.id} -> {self.recipient.username}"
