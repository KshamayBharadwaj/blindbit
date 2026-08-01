from django.core.management.base import BaseCommand
from django.utils import timezone
from vault.models import UploadSession

class Command(BaseCommand):
    help = "Delete expired or abandoned upload sessions and their chunks"

    def handle(self, *args, **options):
        qs = UploadSession.objects.filter(expires_at__lt=timezone.now())
        count = qs.count()
        qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Purged {count} expired upload session(s)"))
