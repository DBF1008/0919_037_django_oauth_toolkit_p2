# Generated for OIDC Session Management and Front-Channel Logout support

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

from oauth2_provider.settings import oauth2_settings


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        migrations.swappable_dependency(oauth2_settings.APPLICATION_MODEL),
        ("oauth2_provider", "0014_alter_help_text"),
    ]

    operations = [
        migrations.AddField(
            model_name="application",
            name="frontchannel_logout_session_required",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, front-channel logout notifications include the "
                    "issuer and the Session ID (sid) of the session being logged out."
                ),
            ),
        ),
        migrations.AddField(
            model_name="application",
            name="frontchannel_logout_uri",
            field=models.URLField(
                blank=True,
                default="",
                help_text=(
                    "Relying Party front-channel logout URI. An iframe to this URI is "
                    "rendered when the End-User logs out at the OpenID Provider."
                ),
                max_length=2048,
            ),
        ),
        migrations.CreateModel(
            name="UserSession",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("session_key", models.CharField(db_index=True, max_length=40)),
                ("op_browser_state", models.CharField(db_index=True, max_length=128)),
                ("session_state_salt", models.CharField(max_length=64)),
                ("session_state", models.CharField(db_index=True, max_length=128)),
                ("expires", models.DateTimeField()),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("updated", models.DateTimeField(auto_now=True)),
                ("revoked", models.DateTimeField(blank=True, null=True)),
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
                        related_name="%(app_label)s_%(class)s",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
                "swappable": "OAUTH2_PROVIDER_USER_SESSION_MODEL",
            },
        ),
        migrations.AddIndex(
            model_name="usersession",
            index=models.Index(fields=["user", "session_key"], name="oauth2_prov_user_id_5dadb1_idx"),
        ),
        migrations.AddIndex(
            model_name="usersession",
            index=models.Index(fields=["revoked", "expires"], name="oauth2_prov_revoked_ab73ae_idx"),
        ),
    ]
