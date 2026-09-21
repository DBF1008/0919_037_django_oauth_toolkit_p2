import json
import re
from datetime import timedelta

import pytest
from django.contrib.auth import get_user
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.models import clear_expired, get_user_session_model
from oauth2_provider.oauth2_validators import OAuth2Validator

from . import presets


UserSession = get_user_session_model()

SESSION_STATE_RE = re.compile(r"^[0-9a-f]{64}\.[0-9a-f]{16}$")


def decode_id_token(id_token, key):
    jwt_token = jwt.JWT(key=key, jwt=id_token)
    return json.loads(jwt_token.claims)


@pytest.mark.django_db(databases="__all__")
class TestSessionStateValidator:
    def test_generate_session_state_format(self, test_user):
        validator = OAuth2Validator()
        session_state = validator.generate_session_state(test_user, "client-id")
        assert SESSION_STATE_RE.match(session_state)

    def test_generate_session_state_random_salt(self, test_user):
        validator = OAuth2Validator()
        first = validator.generate_session_state(test_user, "client-id")
        second = validator.generate_session_state(test_user, "client-id")
        assert first != second

    def test_validate_session_state_roundtrip(self, test_user):
        validator = OAuth2Validator()
        session_state = validator.generate_session_state(test_user, "client-id")
        assert validator.validate_session_state(session_state, test_user, "client-id")

    def test_validate_session_state_wrong_client(self, test_user):
        validator = OAuth2Validator()
        session_state = validator.generate_session_state(test_user, "client-id")
        assert not validator.validate_session_state(session_state, test_user, "other-client-id")

    def test_validate_session_state_wrong_user(self, test_user, other_user):
        validator = OAuth2Validator()
        session_state = validator.generate_session_state(test_user, "client-id")
        assert not validator.validate_session_state(session_state, other_user, "client-id")

    @pytest.mark.parametrize(
        "session_state",
        [
            None,
            "",
            "no-salt",
            ".salt",
            "digest.",
            "deadbeef.salt",
        ],
    )
    def test_validate_session_state_malformed(self, test_user, session_state):
        validator = OAuth2Validator()
        assert not validator.validate_session_state(session_state, test_user, "client-id")

    def test_validate_session_state_tampered_digest(self, test_user):
        validator = OAuth2Validator()
        session_state = validator.generate_session_state(test_user, "client-id")
        digest, salt = session_state.split(".")
        tampered = "{}{}.{}".format("0" if digest[0] != "0" else "1", digest[1:], salt)
        assert not validator.validate_session_state(tampered, test_user, "client-id")

    def test_get_op_browser_state(self, test_user, other_user):
        validator = OAuth2Validator()
        state = validator.get_op_browser_state(test_user)
        assert state
        assert str(test_user.pk) not in state
        assert state == validator.get_op_browser_state(test_user)
        assert state != validator.get_op_browser_state(other_user)


@pytest.mark.django_db(databases="__all__")
class TestUserSessionModel:
    def test_get_or_create_user_session(self, sm_settings, test_user, application):
        validator = OAuth2Validator()
        user_session = validator.get_or_create_user_session(test_user, application)
        assert user_session.pk
        assert user_session.user == test_user
        assert user_session.application == application
        assert SESSION_STATE_RE.match(user_session.session_state)
        assert not user_session.is_expired()
        assert validator.validate_session_state(user_session.session_state, test_user, application.client_id)

    def test_get_or_create_user_session_is_idempotent(self, sm_settings, test_user, application):
        validator = OAuth2Validator()
        first = validator.get_or_create_user_session(test_user, application)
        second = validator.get_or_create_user_session(test_user, application)
        # Concurrent/repeated token issuance reuses the same row and keeps
        # the session state stable instead of failing on the (user,
        # application) uniqueness constraint.
        assert first.pk == second.pk
        assert first.session_state == second.session_state
        assert UserSession.objects.count() == 1

    def test_get_or_create_user_session_regenerates_expired(self, sm_settings, test_user, application):
        validator = OAuth2Validator()
        user_session = validator.get_or_create_user_session(test_user, application)
        user_session.expires = timezone.now() - timedelta(seconds=1)
        user_session.save()
        regenerated = validator.get_or_create_user_session(test_user, application)
        assert regenerated.pk == user_session.pk
        assert regenerated.session_state != user_session.session_state
        assert not regenerated.is_expired()

    def test_user_session_unique_per_user_and_application(self, sm_settings, test_user, application):
        validator = OAuth2Validator()
        validator.get_or_create_user_session(test_user, application)
        with transaction.atomic():
            with pytest.raises(IntegrityError):
                UserSession.objects.create(
                    user=test_user,
                    application=application,
                    session_state="other-state.salt",
                    expires=timezone.now() + timedelta(hours=1),
                )

    def test_user_session_is_expired(self, sm_settings, test_user, application):
        validator = OAuth2Validator()
        user_session = validator.get_or_create_user_session(test_user, application)
        user_session.expires = timezone.now() - timedelta(seconds=1)
        assert user_session.is_expired()

    def test_clear_expired_user_sessions(self, sm_settings, test_user, application):
        validator = OAuth2Validator()
        expired_session = validator.get_or_create_user_session(test_user, application)
        expired_session.expires = timezone.now() - timedelta(seconds=1)
        expired_session.save()
        clear_expired()
        assert not UserSession.objects.filter(pk=expired_session.pk).exists()


@pytest.mark.django_db(databases="__all__")
class TestIDTokenSessionClaims:
    def test_id_token_contains_sid_when_enabled(self, oidc_session_tokens, oidc_key):
        claims = decode_id_token(oidc_session_tokens.id_token, oidc_key)
        assert "sid" in claims
        user_session = UserSession.objects.get(
            user=oidc_session_tokens.user, application=oidc_session_tokens.application
        )
        assert claims["sid"] == user_session.session_state

    def test_id_token_has_no_sid_when_disabled(self, oidc_tokens, oidc_key):
        claims = decode_id_token(oidc_tokens.id_token, oidc_key)
        assert "sid" not in claims
        assert UserSession.objects.count() == 0


@pytest.mark.django_db(databases="__all__")
class TestCheckSessionIframeView:
    def test_get_check_session_iframe(self, sm_settings, logged_in_client):
        response = logged_in_client.get(reverse("oauth2_provider:check-session-iframe"))
        assert response.status_code == 200
        assert response["Cache-Control"] == "no-store"
        # The OP iframe must be embeddable cross-origin in a hidden iframe.
        assert "X-Frame-Options" not in response
        content = response.content.decode()
        assert "postMessage" in content
        assert "op_browser_state" in content

    def test_check_session_iframe_sets_op_browser_state_cookie(
        self, sm_settings, logged_in_client, test_user
    ):
        response = logged_in_client.get(reverse("oauth2_provider:check-session-iframe"))
        cookie = response.cookies["op_browser_state"]
        validator = OAuth2Validator()
        assert cookie.value == validator.get_op_browser_state(test_user)
        assert str(test_user.pk) not in cookie.value

    def test_check_session_iframe_anonymous_deletes_cookie(self, sm_settings, client):
        client.cookies["op_browser_state"] = "stale-value"
        response = client.get(reverse("oauth2_provider:check-session-iframe"))
        assert response.status_code == 200
        assert response.cookies["op_browser_state"].value == ""

    def test_check_session_iframe_renders_allowed_origins(self, sm_settings, logged_in_client, application):
        response = logged_in_client.get(reverse("oauth2_provider:check-session-iframe"))
        content = response.content.decode()
        assert application.client_id in content
        assert "http://example.org" in content

    def test_check_session_iframe_not_enabled(self, oauth2_settings, client):
        oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        response = client.get(reverse("oauth2_provider:check-session-iframe"))
        assert response.status_code == 404

    def test_discovery_contains_check_session_iframe(self, sm_settings, client):
        response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        assert response.status_code == 200
        data = response.json()
        assert data["check_session_iframe"] == "http://localhost/o/check-session-iframe/"

    def test_discovery_without_check_session_iframe_when_disabled(self, oauth2_settings, client):
        oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
        assert response.status_code == 200
        assert "check_session_iframe" not in response.json()


@pytest.mark.django_db(databases="__all__")
class TestFrontChannelLogoutView:
    logout_url = reverse("oauth2_provider:frontchannel-logout")

    def _setup_sessions(self, test_user, application, public_application):
        application.frontchannel_logout_uri = "https://rp1.example/logout"
        application.save()
        public_application.frontchannel_logout_uri = "https://rp2.example/logout"
        public_application.save()
        validator = OAuth2Validator()
        first = validator.get_or_create_user_session(test_user, application)
        second = validator.get_or_create_user_session(test_user, public_application)
        return first, second

    def test_frontchannel_logout_requires_parameters(self, sm_settings, client):
        assert client.get(self.logout_url).status_code == 400
        assert client.get(self.logout_url, {"iss": "http://localhost/o"}).status_code == 400
        assert client.get(self.logout_url, {"sid": "state.salt"}).status_code == 400

    def test_frontchannel_logout_validates_issuer(self, sm_settings, client):
        response = client.get(self.logout_url, {"iss": "http://other.example/o", "sid": "state.salt"})
        assert response.status_code == 400

    def test_frontchannel_logout(
        self, sm_settings, logged_in_client, test_user, application, public_application
    ):
        first, second = self._setup_sessions(test_user, application, public_application)
        response = logged_in_client.get(
            self.logout_url, {"iss": "http://localhost/o", "sid": first.session_state}
        )
        assert response.status_code == 200
        content = response.content.decode()
        # All logged-in RPs are notified concurrently via hidden iframes.
        for user_session in (first, second):
            # "&" is HTML-escaped in the rendered iframe src attribute.
            iframe_url = (
                f"{user_session.application.frontchannel_logout_uri}"
                f"?iss=http%3A%2F%2Flocalhost%2Fo&amp;sid={user_session.session_state}"
            )
            assert iframe_url in content
        # All sessions of the user are terminated.
        assert UserSession.objects.count() == 0
        # The OP Django session is terminated as well.
        assert not get_user(logged_in_client).is_authenticated
        # The OP browser state cookie is rotated so that polling RPs observe
        # a "changed" session state.
        assert response.cookies["op_browser_state"].value == ""

    def test_frontchannel_logout_is_idempotent(
        self, sm_settings, logged_in_client, test_user, application, public_application
    ):
        first, _second = self._setup_sessions(test_user, application, public_application)
        params = {"iss": "http://localhost/o", "sid": first.session_state}
        first_response = logged_in_client.get(self.logout_url, params)
        assert first_response.status_code == 200
        # A concurrent or repeated logout for the same session must not fail.
        second_response = logged_in_client.get(self.logout_url, params)
        assert second_response.status_code == 200
        assert "iframe" not in second_response.content.decode()

    def test_frontchannel_logout_unknown_sid(self, sm_settings, client):
        response = client.get(self.logout_url, {"iss": "http://localhost/o", "sid": "unknown.salt"})
        assert response.status_code == 200
        assert "iframe" not in response.content.decode()

    def test_frontchannel_logout_skips_applications_without_logout_uri(
        self, sm_settings, logged_in_client, test_user, application, public_application
    ):
        # public_application has no frontchannel_logout_uri registered.
        application.frontchannel_logout_uri = "https://rp1.example/logout"
        application.save()
        validator = OAuth2Validator()
        first = validator.get_or_create_user_session(test_user, application)
        validator.get_or_create_user_session(test_user, public_application)
        response = logged_in_client.get(
            self.logout_url, {"iss": "http://localhost/o", "sid": first.session_state}
        )
        assert response.status_code == 200
        content = response.content.decode()
        assert "https://rp1.example/logout" in content
        assert content.count("<iframe") == 1
        assert UserSession.objects.count() == 0

    def test_frontchannel_logout_anonymous_request(self, sm_settings, client, test_user, application):
        application.frontchannel_logout_uri = "https://rp1.example/logout"
        application.save()
        validator = OAuth2Validator()
        user_session = validator.get_or_create_user_session(test_user, application)
        response = client.get(
            self.logout_url, {"iss": "http://localhost/o", "sid": user_session.session_state}
        )
        assert response.status_code == 200
        assert UserSession.objects.count() == 0

    def test_frontchannel_logout_not_enabled(self, oauth2_settings, client):
        oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        response = client.get(self.logout_url, {"iss": "http://localhost/o", "sid": "state.salt"})
        assert response.status_code == 404
