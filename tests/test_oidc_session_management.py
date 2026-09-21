"""
Tests for OpenID Connect Session Management 1.0 and OpenID Connect
Front-Channel Logout 1.0 support.

https://openid.net/specs/openid-connect-session-1_0.html
https://openid.net/specs/openid-connect-frontchannel-1_0.html
"""

import json
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.models import get_user_session_model
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings

from . import presets
from .conftest import CLEARTEXT_SECRET


Application = None
UserModel = None
UserSession = get_user_session_model()


SESSION_MANAGEMENT_SETTINGS = {
    "OIDC_SESSION_MANAGEMENT_ENABLED": True,
}

FRONTCHANNEL_SETTINGS = {
    "OIDC_SESSION_MANAGEMENT_ENABLED": True,
    "OIDC_FRONTCHANNEL_LOGOUT_ENABLED": True,
}


@pytest.fixture
def session_settings(oauth2_settings):
    settings = dict(presets.OIDC_SETTINGS_RP_LOGOUT)
    settings.update(SESSION_MANAGEMENT_SETTINGS)
    oauth2_settings.update(settings)
    return oauth2_settings


@pytest.fixture
def frontchannel_settings(oauth2_settings):
    settings = dict(presets.OIDC_SETTINGS_RP_LOGOUT)
    settings.update(FRONTCHANNEL_SETTINGS)
    oauth2_settings.update(settings)
    return oauth2_settings


@pytest.fixture
def frontchannel_application(application):
    application.frontchannel_logout_uri = "https://rp.example.com/frontchannel-logout"
    application.frontchannel_logout_session_required = True
    application.save()
    return application


# ---------------------------------------------------------------------------
# session_state generation and validation
# ---------------------------------------------------------------------------


class TestSessionState:
    def test_calculate_session_state_shape(self):
        state = OAuth2Validator.calculate_session_state("client", "https://rp.example", "op-state", "salt")
        digest, _, salt = state.partition(".")
        assert salt == "salt"
        assert len(digest) == 64

    def test_session_state_matches_reference_algorithm(self):
        import hashlib

        expected = hashlib.sha256(b"client https://rp.example op-state salt").hexdigest() + ".salt"
        assert (
            OAuth2Validator.calculate_session_state("client", "https://rp.example", "op-state", "salt")
            == expected
        )

    def test_validate_session_state_valid(self):
        state = OAuth2Validator.calculate_session_state("client", "https://rp.example", "op-state", "salt")
        assert OAuth2Validator.validate_session_state("client", "https://rp.example", "op-state", state)

    @pytest.mark.parametrize(
        "client_id,origin,op_state,state",
        [
            ("other", "https://rp.example", "op-state", None),
            ("client", "https://other.example", "op-state", None),
            ("client", "https://rp.example", "other-state", None),
            ("client", "https://rp.example", "op-state", "garbage"),
            ("client", "https://rp.example", "op-state", "garbage."),
            ("client", "https://rp.example", "op-state", ".salt"),
            ("", "https://rp.example", "op-state", None),
        ],
    )
    def test_validate_session_state_invalid(self, client_id, origin, op_state, state):
        if state is None:
            state = OAuth2Validator.calculate_session_state(
                "client", "https://rp.example", "op-state", "salt"
            )
        assert not OAuth2Validator.validate_session_state(client_id, origin, op_state, state)

    def test_tampered_salt_is_rejected(self):
        state = OAuth2Validator.calculate_session_state("client", "https://rp.example", "op-state", "salt")
        tampered = state[:-1] + ("t" if state[-1] != "t" else "x")
        assert not OAuth2Validator.validate_session_state(
            "client", "https://rp.example", "op-state", tampered
        )

    def test_generate_salt_and_state_are_unique(self):
        salt_a = OAuth2Validator.generate_session_state_salt()
        salt_b = OAuth2Validator.generate_session_state_salt()
        assert salt_a != salt_b
        state_a = OAuth2Validator.generate_op_browser_state()
        state_b = OAuth2Validator.generate_op_browser_state()
        assert state_a != state_b

    def test_get_origin(self):
        assert OAuth2Validator.get_origin("https://rp.example:8443/path?x=1") == "https://rp.example:8443"
        assert OAuth2Validator.get_origin("not-a-url") == ""
        assert OAuth2Validator.get_origin("") == ""

    def test_user_session_build_session_state(self):
        import hashlib

        state = UserSession.build_session_state("client-id", 42, "salt")
        expected = hashlib.sha256(b"saltclient-id42").hexdigest() + ".salt"
        assert state == expected
        # Deterministic inputs reproduce the value; changed user yields a new one.
        assert UserSession.build_session_state("client-id", 42, "salt") == expected
        assert UserSession.build_session_state("client-id", 43, "salt") != expected


# ---------------------------------------------------------------------------
# UserSession model
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestUserSessionModel:
    def test_revoke_is_idempotent(self, test_user, application):
        session = UserSession.objects.create(
            user=test_user,
            application=application,
            session_key="session-key",
            op_browser_state="op-state",
            session_state_salt="salt",
            session_state="digest.salt",
            expires=timezone.now() + timedelta(hours=1),
        )
        assert session.revoke() is True
        session.refresh_from_db()
        revoked_at = session.revoked
        assert revoked_at is not None
        # A concurrent/repeated logout must not overwrite the timestamp.
        assert session.revoke() is False
        session.refresh_from_db()
        assert session.revoked == revoked_at

    def test_is_active(self, test_user, application):
        active = UserSession.objects.create(
            user=test_user,
            application=application,
            session_key="a",
            op_browser_state="s",
            session_state_salt="salt",
            session_state="d.salt",
            expires=timezone.now() + timedelta(hours=1),
        )
        assert active.is_active()
        active.revoke()
        assert not active.is_active()

        expired = UserSession.objects.create(
            user=test_user,
            application=application,
            session_key="b",
            op_browser_state="s",
            session_state_salt="salt",
            session_state="d.salt",
            expires=timezone.now() - timedelta(hours=1),
        )
        assert not expired.is_active()


# ---------------------------------------------------------------------------
# check_session_iframe endpoint
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestCheckSessionIframe:
    url = reverse("oauth2_provider:oidc-check-session-iframe")

    def test_disabled_returns_404(self, client, oauth2_settings):
        oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        response = client.get(self.url)
        assert response.status_code == 404

    def test_enabled_serves_iframe(self, client, session_settings, application):
        response = client.get(self.url)
        assert response.status_code == 200
        content = response.content.decode()
        assert "addEventListener" in content
        assert "op_browser_state" in content
        assert "http://example.org" in content
        # Cross-origin framing policy and cache control
        assert "frame-ancestors" in response["Content-Security-Policy"]
        assert response["Cache-Control"] == "no-store"

    def test_allowed_origins_include_redirect_and_frontchannel_uris(
        self, client, session_settings, frontchannel_application
    ):
        response = client.get(self.url)
        origins = json.loads(response.content.decode().split("ALLOWED_ORIGINS = ")[1].split(";", 1)[0])
        assert "http://example.org" in origins
        assert "https://rp.example.com" in origins

    def test_frame_ancestors_none_without_applications(self, client, session_settings):
        response = client.get(self.url)
        assert "frame-ancestors 'none'" in response["Content-Security-Policy"]


# ---------------------------------------------------------------------------
# session_state on the Authentication Response
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_authorization_response_contains_session_state(client, test_user, session_settings, application):
    client.force_login(test_user)
    response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    assert response.status_code == 302
    query = parse_qs(urlparse(response["Location"]).query)
    assert "session_state" in query
    session_state = query["session_state"][0]
    assert " " not in session_state
    assert "." in session_state

    # The OP User Agent state cookie is issued alongside the redirect
    cookie = response.cookies[oauth2_settings.OIDC_SESSION_COOKIE_NAME]
    assert cookie["httponly"] == ""
    assert cookie.value

    # A matching UserSession row backs the value
    user_session = UserSession.objects.get(application=application, user=test_user)
    assert user_session.session_state == session_state
    assert OAuth2Validator.validate_session_state(
        application.client_id, "http://example.org", cookie.value, session_state
    )


@pytest.mark.django_db
def test_no_session_state_when_disabled(client, test_user, oauth2_settings, application):
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    client.force_login(test_user)
    response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random",
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    query = parse_qs(urlparse(response["Location"]).query)
    assert "session_state" not in query
    assert oauth2_settings.OIDC_SESSION_COOKIE_NAME not in response.cookies
    assert UserSession.objects.count() == 0


@pytest.mark.django_db
def test_check_session_detects_change_after_cookie_change(client, test_user, session_settings, application):
    client.force_login(test_user)
    response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    query = parse_qs(urlparse(response["Location"]).query)
    session_state = query["session_state"][0]
    cookie_value = response.cookies[oauth2_settings.OIDC_SESSION_COOKIE_NAME].value

    # Same browser state -> unchanged
    assert OAuth2Validator.validate_session_state(
        application.client_id, "http://example.org", cookie_value, session_state
    )
    # A logout changes the OP User Agent state -> changed
    assert not OAuth2Validator.validate_session_state(
        application.client_id, "http://example.org", "rotated-state", session_state
    )


# ---------------------------------------------------------------------------
# Front-Channel Logout endpoint
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestFrontChannelLogout:
    url = reverse("oauth2_provider:oidc-front-channel-logout")

    def _create_session(self, user, application, session_key="sid-123"):
        salt = OAuth2Validator.generate_session_state_salt()
        state = OAuth2Validator.calculate_session_state(
            application.client_id, "https://rp.example.com", "op-state", salt
        )
        return UserSession.objects.create(
            user=user,
            application=application,
            session_key=session_key,
            op_browser_state="op-state",
            session_state_salt=salt,
            session_state=state,
            expires=timezone.now() + timedelta(hours=1),
        )

    def test_disabled_returns_404(self, client, oauth2_settings):
        oauth2_settings.update(presets.OIDC_SETTINGS_RW)
        assert client.get(self.url).status_code == 404

    def test_iframe_rendered_for_all_rps_of_sid(
        self, client, frontchannel_settings, test_user, frontchannel_application
    ):
        self._create_session(test_user, frontchannel_application)
        response = client.get(self.url, data={"sid": "sid-123"})
        assert response.status_code == 200
        content = response.content.decode()
        assert frontchannel_application.frontchannel_logout_uri in content
        assert "iss=" in content
        assert "sid=sid-123" in content

    def test_invalid_issuer_rejected(
        self, client, frontchannel_settings, test_user, frontchannel_application
    ):
        self._create_session(test_user, frontchannel_application)
        response = client.get(self.url, data={"sid": "sid-123", "iss": "https://evil.example"})
        assert response.status_code == 400

    def test_valid_issuer_accepted(self, client, frontchannel_settings, test_user, frontchannel_application):
        self._create_session(test_user, frontchannel_application)
        issuer = oauth2_settings.OIDC_ISS_ENDPOINT
        response = client.get(self.url, data={"sid": "sid-123", "iss": issuer})
        assert response.status_code == 200

    def test_session_required_without_sid_skips_application(
        self, client, frontchannel_settings, test_user, application
    ):
        # Application without frontchannel_logout_uri configured.
        UserSession.objects.all().delete()
        self._create_session(test_user, application)
        response = client.get(self.url, data={"sid": "sid-123"})
        assert b"<iframe" not in response.content

    def test_idempotent_repeated_logout(
        self, client, frontchannel_settings, test_user, frontchannel_application
    ):
        session = self._create_session(test_user, frontchannel_application)
        first = client.get(self.url, data={"sid": "sid-123"})
        assert first.status_code == 200
        revoked_first = UserSession.objects.get(pk=session.pk).revoked
        assert revoked_first is not None
        # Second concurrent call renders the page but does not error and no
        # longer notifies the already-revoked session (idempotent).
        second = client.get(self.url, data={"sid": "sid-123"})
        assert second.status_code == 200
        assert b"<iframe" not in second.content
        assert UserSession.objects.get(pk=session.pk).revoked == revoked_first

    def test_rotates_op_browser_state_cookie(
        self, client, frontchannel_settings, test_user, frontchannel_application
    ):
        self._create_session(test_user, frontchannel_application)
        client.cookies[oauth2_settings.OIDC_SESSION_COOKIE_NAME] = "op-state"
        response = client.get(self.url, data={"sid": "sid-123"})
        assert oauth2_settings.OIDC_SESSION_COOKIE_NAME in response.cookies
        assert response.cookies[oauth2_settings.OIDC_SESSION_COOKIE_NAME].value == ""

    def test_unknown_sid_renders_empty_page(
        self, client, frontchannel_settings, test_user, frontchannel_application
    ):
        self._create_session(test_user, frontchannel_application)
        response = client.get(self.url, data={"sid": "unknown"})
        assert response.status_code == 200
        assert b"<iframe" not in response.content
        assert UserSession.objects.get(session_key="sid-123").revoked is None

    def test_open_redirect_is_blocked(self, client, frontchannel_settings):
        response = client.get(
            self.url,
            data={"post_logout_redirect_uri": "https://evil.example/path"},
        )
        assert b"evil.example" not in response.content

    def test_same_origin_redirect_allowed(self, client, frontchannel_settings):
        response = client.get(
            self.url,
            data={"post_logout_redirect_uri": "/logged-out/"},
        )
        assert b"/logged-out/" in response.content

    def test_no_sid_uses_authenticated_user(
        self, client, frontchannel_settings, test_user, frontchannel_application
    ):
        self._create_session(test_user, frontchannel_application, session_key="sid-a")
        client.force_login(test_user)
        response = client.get(self.url)
        assert b"sid=sid-a" in response.content

    def test_build_frontchannel_logout_uri_without_session_required(self, frontchannel_settings, application):
        application.frontchannel_logout_uri = "https://rp.example.com/logout?existing=1"
        uri = FrontChannelLogoutUriHelper.build(application, "https://op.example", "sid")
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        assert query["iss"] == ["https://op.example"]
        assert "sid" not in query
        assert query["existing"] == ["1"]


class FrontChannelLogoutUriHelper:
    @staticmethod
    def build(application, issuer, sid):
        from oauth2_provider.views.oidc import FrontChannelLogoutView

        return FrontChannelLogoutView.build_frontchannel_logout_uri(application, issuer, sid)


# ---------------------------------------------------------------------------
# Discovery metadata
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_discovery_includes_session_metadata(client, session_settings):
    response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
    data = response.json()
    assert data["check_session_iframe"].endswith("/check_session_iframe/")
    assert "frontchannel_logout_supported" not in data


@pytest.mark.django_db
def test_discovery_includes_frontchannel_metadata(client, frontchannel_settings):
    response = client.get(reverse("oauth2_provider:oidc-connect-discovery-info"))
    data = response.json()
    assert data["check_session_iframe"]
    assert data["frontchannel_logout_supported"] is True
    assert data["frontchannel_logout_session_supported"] is True


@pytest.mark.django_db
def test_discovery_without_session_metadata_by_default(client, oauth2_settings):
    oauth2_settings.update(presets.OIDC_SETTINGS_RW)
    data = client.get(reverse("oauth2_provider:oidc-connect-discovery-info")).json()
    assert "check_session_iframe" not in data
    assert "frontchannel_logout_supported" not in data


# ---------------------------------------------------------------------------
# sid Claim in the ID Token and RP-Initiated Logout integration
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_id_token_contains_sid_with_frontchannel_logout(
    client, test_user, frontchannel_settings, frontchannel_application
):
    client.force_login(test_user)
    auth_response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": frontchannel_application.client_id,
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    code = parse_qs(urlparse(auth_response["Location"]).query)["code"][0]
    client.logout()
    token_response = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": frontchannel_application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        },
    )
    assert token_response.status_code == 200
    id_token = token_response.json()["id_token"]
    claims = json.loads(jwt.JWT(key=None, jwt=id_token, check_claims={}).token.objects["payload"])
    user_session = UserSession.objects.get(application=frontchannel_application, user=test_user)
    assert claims["sid"] == user_session.sid


@pytest.mark.django_db
def test_id_token_has_no_sid_when_frontchannel_disabled(client, test_user, session_settings, application):
    client.force_login(test_user)
    auth_response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    code = parse_qs(urlparse(auth_response["Location"]).query)["code"][0]
    client.logout()
    token_response = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        },
    )
    id_token = token_response.json()["id_token"]
    claims = json.loads(jwt.JWT(key=None, jwt=id_token, check_claims={}).token.objects["payload"])
    assert "sid" not in claims


@pytest.mark.django_db
def test_rp_initiated_logout_renders_frontchannel_iframes(
    client, test_user, frontchannel_settings, frontchannel_application, oidc_key
):
    client.force_login(test_user)
    # Establish the OIDC session and obtain an ID Token for id_token_hint.
    auth_response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": frontchannel_application.client_id,
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    code = parse_qs(urlparse(auth_response["Location"]).query)["code"][0]
    client.logout()
    token_response = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": frontchannel_application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        },
    )
    id_token_hint = token_response.json()["id_token"]

    sid = UserSession.objects.get(application=frontchannel_application, user=test_user).sid
    client.force_login(test_user)

    response = client.get(
        reverse("oauth2_provider:rp-initiated-logout"), data={"id_token_hint": id_token_hint}
    )
    assert response.status_code == 200
    content = response.content.decode()
    assert frontchannel_application.frontchannel_logout_uri in content
    assert f"sid={sid}" in content
    # The OP User Agent state cookie is cleared so check_session reports "changed"
    assert oauth2_settings.OIDC_SESSION_COOKIE_NAME in response.cookies
    assert UserSession.objects.get(session_key=sid).revoked is not None


# ---------------------------------------------------------------------------
# Session expiration cleanup
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_clear_expired_removes_expired_and_revoked_user_sessions(test_user, application):
    from oauth2_provider.models import clear_expired

    now = timezone.now()
    active = UserSession.objects.create(
        user=test_user,
        application=application,
        session_key="active",
        op_browser_state="s",
        session_state_salt="salt",
        session_state="d.salt",
        expires=now + timedelta(hours=1),
    )
    UserSession.objects.create(
        user=test_user,
        application=application,
        session_key="expired",
        op_browser_state="s",
        session_state_salt="salt",
        session_state="d.salt",
        expires=now - timedelta(hours=1),
    )
    UserSession.objects.create(
        user=test_user,
        application=application,
        session_key="revoked",
        op_browser_state="s",
        session_state_salt="salt",
        session_state="d.salt",
        expires=now + timedelta(hours=1),
        revoked=now,
    )

    clear_expired()

    remaining_sids = set(UserSession.objects.values_list("session_key", flat=True))
    assert remaining_sids == {active.session_key}


@pytest.mark.django_db
def test_sid_is_shared_across_rps_in_one_browser_session(
    client, test_user, frontchannel_settings, application, public_application
):
    """All UserSessions created in one OP browser session share the same sid."""
    client.force_login(test_user)

    def authorize(app, redirect_uri):
        response = client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": app.client_id,
                "scope": "openid",
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "allow": True,
            },
        )
        assert response.status_code == 302
        return parse_qs(urlparse(response["Location"]).query)["session_state"][0]

    authorize(application, "http://example.org")
    authorize(public_application, "http://other.org")

    sids = set(UserSession.objects.values_list("session_key", flat=True))
    assert len(sids) == 1
    assert sids != {""}


@pytest.mark.django_db
def test_frontchannel_logout_notifies_all_rps_of_session(
    client, frontchannel_settings, test_user, application, public_application
):
    """A logout by sid notifies every RP that registered a logout URI."""
    application.frontchannel_logout_uri = "https://rp1.example.com/logout"
    application.save()
    public_application.frontchannel_logout_uri = "https://rp2.example.com/logout"
    public_application.save()

    salt = OAuth2Validator.generate_session_state_salt()
    for app in (application, public_application):
        UserSession.objects.create(
            user=test_user,
            application=app,
            session_key="shared-sid",
            op_browser_state="op-state",
            session_state_salt=salt,
            session_state=OAuth2Validator.calculate_session_state(
                app.client_id, "https://rp.example", "op-state", salt
            ),
            expires=timezone.now() + timedelta(hours=1),
        )

    response = client.get(reverse("oauth2_provider:oidc-front-channel-logout"), data={"sid": "shared-sid"})
    content = response.content.decode()
    assert "https://rp1.example.com/logout" in content
    assert "https://rp2.example.com/logout" in content
    assert content.count("<iframe") == 2


@pytest.mark.django_db
def test_session_state_cookie_attributes(client, test_user, session_settings, application):
    client.force_login(test_user)
    response = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "scope": "openid",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        },
    )
    cookie = response.cookies[oauth2_settings.OIDC_SESSION_COOKIE_NAME]
    # Readable by the OP iframe JavaScript (spec Section 3.2)
    assert cookie["httponly"] == ""
    # Cross-site (RP page embeds the OP iframe) and bound to the scheme
    assert cookie["samesite"] == "None"
    # The test client uses plain HTTP; secure mirrors request.is_secure().
    assert cookie["secure"] == ""
    assert int(cookie["max-age"]) == oauth2_settings.OIDC_SESSION_COOKIE_AGE
