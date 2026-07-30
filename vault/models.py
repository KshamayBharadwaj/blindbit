import uuid
from django.db import models
from django.conf import settings

class EncryptedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files')
    ciphertext = models.BinaryField(help_text="AES-256-GCM encrypted file contents")
    wrapped_file_key = models.TextField(help_text="File Key wrapped under the owner's Master Key")
    encrypted_filename = models.TextField(help_text="AES-256-GCM encrypted filename")
    encrypted_metadata = models.TextField(blank=True, help_text="Encrypted JSON with size, MIME type, tags")
    nonce = models.TextField(help_text="AES-GCM nonce used for file encryption")
    auth_tag = models.TextField(help_text="AES-GCM authentication tag")
    original_size = models.BigIntegerField(default=0)
    mime_type = models.CharField(max_length=255, default='application/octet-stream')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"File {self.id} owned by {self.owner.username}"
