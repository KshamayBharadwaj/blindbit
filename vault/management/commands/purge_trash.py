from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from vault.models import EncryptedFile

class Command(BaseCommand):
    help = "Permanently delete files that have been in the Trash past the retention period"

    def handle(self, *args, **options):
        retention_days = getattr(settings, 'TRASH_RETENTION_DAYS', 30)
        cutoff = timezone.now() - timedelta(days=retention_days)
        qs = EncryptedFile.all_objects.filter(deleted_at__isnull=False, deleted_at__lt=cutoff)
        count = qs.count()
        qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Purged {count} expired trashed file(s)"))
