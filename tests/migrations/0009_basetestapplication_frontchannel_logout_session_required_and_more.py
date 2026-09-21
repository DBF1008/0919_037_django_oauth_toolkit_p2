# Generated for OIDC Session Management and Front-Channel Logout support

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tests", "0008_sampledevicegrant"),
    ]

    operations = [
        migrations.AddField(
            model_name="basetestapplication",
            name="frontchannel_logout_session_required",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, front-channel logout notifications include the issuer and the "
                    "Session ID (sid) of the session being logged out."
                ),
            ),
        ),
        migrations.AddField(
            model_name="basetestapplication",
            name="frontchannel_logout_uri",
            field=models.URLField(
                blank=True,
                default="",
                help_text=(
                    "Relying Party front-channel logout URI. An iframe to this URI is rendered when "
                    "the End-User logs out at the OpenID Provider."
                ),
                max_length=2048,
            ),
        ),
        migrations.AddField(
            model_name="sampleapplication",
            name="frontchannel_logout_session_required",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When enabled, front-channel logout notifications include the issuer and the "
                    "Session ID (sid) of the session being logged out."
                ),
            ),
        ),
        migrations.AddField(
            model_name="sampleapplication",
            name="frontchannel_logout_uri",
            field=models.URLField(
                blank=True,
                default="",
                help_text=(
                    "Relying Party front-channel logout URI. An iframe to this URI is rendered when "
                    "the End-User logs out at the OpenID Provider."
                ),
                max_length=2048,
            ),
        ),
    ]
