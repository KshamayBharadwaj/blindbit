import uuid
from django.db import models
from django.conf import settings

class ActiveManager(models.Manager):
    """Default manager: excludes files sitting in the trash."""
    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)

class VaultFolder(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='folders')
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    is_favorites = models.BooleanField(default=False, help_text="Auto-created smart folder listing starred files")

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"Folder {self.name} owned by {self.owner.username}"

class EncryptedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files')
    folder = models.ForeignKey(VaultFolder, null=True, blank=True, on_delete=models.SET_NULL, related_name='files')
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
    last_opened_at = models.DateTimeField(null=True, blank=True, help_text="Last time the file was opened/decrypted")
    is_favorite = models.BooleanField(default=False, help_text="Starred for quick access")
    deleted_at = models.DateTimeField(null=True, blank=True, help_text="When the file was moved to Trash; NULL means active")

    objects = ActiveManager()
    all_objects = models.Manager()

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"File {self.id} owned by {self.owner.username}"

class UploadSession(models.Model):
    """Pending chunked upload owned by a user, before it is assembled into an EncryptedFile."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='upload_sessions')
    folder = models.ForeignKey(VaultFolder, null=True, blank=True, on_delete=models.SET_NULL, related_name='upload_sessions')
    token = models.CharField(max_length=64, unique=True, db_index=True, help_text="Secret credential sent with every chunk request")
    encrypted_filename = models.TextField()
    wrapped_file_key = models.TextField()
    nonce = models.TextField(help_text="8-byte random prefix shared by every chunk IV")
    mime_type = models.CharField(max_length=255, default='application/octet-stream')
    original_size = models.BigIntegerField(default=0)
    chunk_size = models.IntegerField(default=8388608)
    total_chunks = models.IntegerField(default=0)
    chunks_received = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"UploadSession {self.id} ({self.chunks_received}/{self.total_chunks} chunks)"

class FileChunk(models.Model):
    """One encrypted chunk of a pending upload."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(UploadSession, on_delete=models.CASCADE, related_name='chunks')
    index = models.IntegerField()
    ciphertext = models.BinaryField(help_text="AES-GCM ciphertext, 16-byte auth tag stripped")
    nonce = models.TextField(help_text="Per-chunk 12-byte IV (8-byte prefix + chunk index)")
    auth_tag = models.TextField(help_text="Per-chunk 16-byte AES-GCM auth tag")

    class Meta:
        unique_together = ['session', 'index']
        ordering = ['index']

    def __str__(self):
        return f"Chunk {self.index} of {self.session_id}"
