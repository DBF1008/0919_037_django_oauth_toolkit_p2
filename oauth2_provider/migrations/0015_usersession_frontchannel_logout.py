import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):

    dependencies = [
        ("oauth2_provider", "0014_alter_help_text"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        migrations.swappable_dependency(oauth2_settings.APPLICATION_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="application",
            name="frontchannel_logout_uri",
            field=models.URLField(
                blank=True,
                default="",
                help_text="Front-Channel Logout URI notified by the OP on logout",
            ),
        ),
        migrations.CreateModel(
            name="UserSession",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("session_state", models.CharField(max_length=255, unique=True)),
                ("expires", models.DateTimeField()),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("updated", models.DateTimeField(auto_now=True)),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=oauth2_settings.APPLICATION_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="oauth2_provider_usersession",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "swappable": "OAUTH2_PROVIDER_USER_SESSION_MODEL",
            },
        ),
        migrations.AddConstraint(
            model_name="usersession",
            constraint=models.UniqueConstraint(
                fields=("user", "application"),
                name="oauth2_provider_usersession_unique_user_application",
            ),
        ),
    ]
