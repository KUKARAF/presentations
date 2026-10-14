import asyncio
import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.v1.auth import oidc
from api.v1.auth.config import SESSION_COOKIE_NAME
from api.v1.auth.router import API_V1_AUTH_ROUTER
from models.sql.api_key import ApiKey
from models.sql.user import User
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey
from services.database import get_async_session

ISSUER = "https://idp.test/application/o/presenton/"
CLIENT_ID = "presenton-client"
CLIENT_SECRET = "presenton-secret"
APP_URL = "https://app.test"
CALLBACK = f"{APP_URL}/api/v1/auth/oidc/callback"


class FakeIdentityProvider:
    """Serves discovery, JWKS and the token endpoint for one RSA signing key."""

    def __init__(self):
        self.key = RSAKey.generate_key(2048, {"kid": "test-key"}, private=True)
        self.nonce_for_next_token: str | None = None
        self.subject = "sub-alice"
        self.extra_claims: dict = {}
        self.code_verifier_seen: str | None = None
        self.code_challenge_seen: str | None = None
        self.token_requests = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}authorize/",
                    "token_endpoint": f"{ISSUER}token/",
                    "jwks_uri": f"{ISSUER}jwks/",
                },
            )
        if request.url.path.endswith("/jwks/"):
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if request.url.path.endswith("/token/"):
            self.token_requests += 1
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            verifier = form.get("code_verifier", "")
            self.code_verifier_seen = verifier
            digest = hashlib.sha256(verifier.encode()).digest()
            if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != self.code_challenge_seen:
                return httpx.Response(400, json={"error": "invalid_grant"})
            if form.get("code") != "good-code":
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={
                    "access_token": "access-token",
                    "token_type": "Bearer",
                    "id_token": self._id_token(),
                },
            )
        return httpx.Response(404)

    def _id_token(self) -> str:
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": self.subject,
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce_for_next_token,
            "preferred_username": "alice",
            "email": "alice@example.com",
            **self.extra_claims,
        }
        return joserfc_jwt.encode({"alg": "RS256", "kid": "test-key"}, payload, self.key)


def _build_client(tmp_path) -> tuple[TestClient, object]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'oidc.db'}")
    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    async def create_tables():
        async with engine.begin() as connection:
            await connection.run_sync(User.__table__.create)
            await connection.run_sync(ApiKey.__table__.create)

    asyncio.run(create_tables())

    async def override_session():
        async with session_maker() as session:
            yield session

    app = FastAPI()
    app.include_router(API_V1_AUTH_ROUTER)
    app.dependency_overrides[get_async_session] = override_session
    return TestClient(app), engine


@pytest.fixture
def idp(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER_URL", ISSUER)
    monkeypatch.setenv("OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("OIDC_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("PRESENTON_PUBLIC_URL", APP_URL)
    monkeypatch.delenv("OIDC_REDIRECT_URI", raising=False)
    monkeypatch.delenv("OIDC_ADMIN_GROUP", raising=False)
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    provider = FakeIdentityProvider()
    monkeypatch.setattr(oidc, "OIDC_HTTP_TRANSPORT", httpx.MockTransport(provider.handler))
    return provider


def _start_login(client: TestClient, provider: FakeIdentityProvider) -> tuple[str, str]:
    response = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"{ISSUER}authorize/?")
    query = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    assert query["code_challenge_method"] == "S256"
    assert query["redirect_uri"] == CALLBACK
    assert "openid" in query["scope"].split()
    provider.nonce_for_next_token = query["nonce"]
    provider.code_challenge_seen = query["code_challenge"]
    return query["state"], query["nonce"]


def test_oidc_login_and_callback_creates_session_for_any_authenticated_user(idp, tmp_path):
    client, _engine = _build_client(tmp_path)

    status = client.get("/api/v1/auth/status").json()
    assert status["configured"] is True
    assert status["authenticated"] is False
    assert status["oidc_enabled"] is True

    state, _nonce = _start_login(client, idp)
    callback = client.get(
        f"/api/v1/auth/oidc/callback?code=good-code&state={state}",
        follow_redirects=False,
    )

    assert callback.status_code == 302
    assert callback.headers["location"] == "/"
    assert SESSION_COOKIE_NAME in callback.cookies
    assert idp.code_verifier_seen  # PKCE verifier was sent on the token request

    me = client.get("/api/v1/auth/status").json()
    assert me["authenticated"] is True
    assert me["username"] == "alice"
    assert me["role"] == "admin"  # first OIDC account on an instance with no admin

    # A second sign-in by the same subject reuses the account.
    client.cookies.clear()
    state, _nonce = _start_login(client, idp)
    second = client.get(
        f"/api/v1/auth/oidc/callback?code=good-code&state={state}",
        follow_redirects=False,
    )
    assert second.status_code == 302
    assert client.get("/api/v1/auth/status").json()["username"] == "alice"


def test_second_oidc_user_is_not_admin_and_username_collisions_are_suffixed(idp, tmp_path):
    client, engine = _build_client(tmp_path)

    state, _ = _start_login(client, idp)
    client.get(f"/api/v1/auth/oidc/callback?code=good-code&state={state}", follow_redirects=False)
    client.cookies.clear()

    idp.subject = "sub-bob"
    idp.extra_claims = {"preferred_username": "alice"}  # same display name as the first user
    state, _ = _start_login(client, idp)
    client.get(f"/api/v1/auth/oidc/callback?code=good-code&state={state}", follow_redirects=False)

    me = client.get("/api/v1/auth/status").json()
    assert me["authenticated"] is True
    assert me["username"] != "alice"
    assert me["username"].startswith("alice-")
    assert me["role"] == "user"

    async def count_users():
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            return await session.scalar(select(func.count()).select_from(User))

    assert asyncio.run(count_users()) == 2


def test_admin_group_controls_admin_role(idp, tmp_path, monkeypatch):
    monkeypatch.setenv("OIDC_ADMIN_GROUP", "presenton-admins")
    client, _engine = _build_client(tmp_path)

    idp.extra_claims = {"groups": ["staff"]}
    state, _ = _start_login(client, idp)
    client.get(f"/api/v1/auth/oidc/callback?code=good-code&state={state}", follow_redirects=False)
    assert client.get("/api/v1/auth/status").json()["role"] == "user"

    client.cookies.clear()
    idp.extra_claims = {"groups": ["staff", "presenton-admins"]}
    state, _ = _start_login(client, idp)
    client.get(f"/api/v1/auth/oidc/callback?code=good-code&state={state}", follow_redirects=False)
    assert client.get("/api/v1/auth/status").json()["role"] == "admin"


def test_callback_rejects_state_mismatch_without_session(idp, tmp_path):
    client, _engine = _build_client(tmp_path)
    _start_login(client, idp)

    response = client.get(
        "/api/v1/auth/oidc/callback?code=good-code&state=forged",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/?reason=oidc_failed"
    assert SESSION_COOKIE_NAME not in response.cookies
    assert client.get("/api/v1/auth/status").json()["authenticated"] is False


def test_callback_rejects_callback_without_login_state(idp, tmp_path):
    client, _engine = _build_client(tmp_path)

    response = client.get(
        "/api/v1/auth/oidc/callback?code=good-code&state=anything",
        follow_redirects=False,
    )

    assert response.headers["location"] == "/?reason=oidc_failed"
    assert SESSION_COOKIE_NAME not in response.cookies


def test_callback_rejects_id_token_with_wrong_nonce(idp, tmp_path):
    client, _engine = _build_client(tmp_path)
    state, _ = _start_login(client, idp)
    idp.nonce_for_next_token = "not-the-nonce-we-sent"

    response = client.get(
        f"/api/v1/auth/oidc/callback?code=good-code&state={state}",
        follow_redirects=False,
    )

    assert response.headers["location"] == "/?reason=oidc_failed"
    assert SESSION_COOKIE_NAME not in response.cookies


def test_local_password_sign_in_is_disabled_when_oidc_is_enabled(idp, tmp_path):
    client, _engine = _build_client(tmp_path)

    setup = client.post("/api/v1/auth/setup", json={"username": "admin", "password": "secret123"})
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret123"})

    assert setup.status_code == 403
    assert login.status_code == 403
    assert SESSION_COOKIE_NAME not in login.cookies


def test_oidc_routes_are_hidden_when_disabled(idp, tmp_path, monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    client, _engine = _build_client(tmp_path)

    assert client.get("/api/v1/auth/oidc/login", follow_redirects=False).status_code == 404
    status = client.get("/api/v1/auth/status").json()
    assert status["oidc_enabled"] is False
    assert status["configured"] is False
