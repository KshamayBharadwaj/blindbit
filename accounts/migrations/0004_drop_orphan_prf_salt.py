from django.db import migrations


def drop_orphan_prf_salt(apps, schema_editor):
    """Remove the orphaned accounts_user.prf_salt column left on databases that
    applied the since-deleted 0004_user_prf_salt migration. The column is NOT
    NULL without a default, which breaks every user creation. No-op elsewhere."""
    vendor = getattr(schema_editor.connection, 'vendor', '')
    if vendor == 'sqlite':
        with schema_editor.connection.cursor() as cursor:
            cursor.execute('PRAGMA table_info(accounts_user)')
            columns = [row[1] for row in cursor.fetchall()]
            if 'prf_salt' in columns:
                cursor.execute('ALTER TABLE accounts_user DROP COLUMN prf_salt')
    elif vendor == 'postgresql':
        with schema_editor.connection.cursor() as cursor:
            cursor.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='accounts_user' AND column_name='prf_salt'"
            )
            if cursor.fetchone():
                cursor.execute('ALTER TABLE accounts_user DROP COLUMN prf_salt')


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_user_passphrase_verifier'),
    ]

    operations = [
        migrations.RunPython(drop_orphan_prf_salt, migrations.RunPython.noop),
    ]
