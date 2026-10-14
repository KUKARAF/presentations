"""OpenID Connect sign-in (authorization code flow with PKCE) for Authentik.

When OIDC_ENABLED is true, browsers sign in through the identity provider and
then receive the same signed session cookie as local sign-in, so every existing
session check keeps working. Any user the provider authenticates is admitted;
who may sign in is decided by the Authentik application's policy bindings.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import time
from typing import Any

import httpx
import jwt
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from joserfc import jwt as joserfc_jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from api.v1.auth.config import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    get_or_create_auth_secret,
)
from api.v1.auth.users import PASSWORD_HELPER, get_jwt_strategy
from models.sql.user import User
from services.database import get_async_session
from utils.get_env import (
    get_oidc_admin_group,
    get_oidc_client_id,
    get_oidc_client_secret,
    get_oidc_issuer_url,
    get_oidc_redirect_uri_env,
    get_oidc_scopes,
    get_presenton_public_url,
    is_oidc_enabled,
)

logger = logging.getLogger(__name__)

OIDC_ROUTER = APIRouter(prefix="/oidc", tags=["Auth"])

OIDC_CALLBACK_PATH = "/api/v1/auth/oidc/callback"
OIDC_COOKIE_PATH = "/api/v1/auth/oidc"
OIDC_STATE_COOKIE_NAME = "presenton_oidc_state"
OIDC_STATE_TTL_SECONDS = 600
OIDC_HTTP_TIMEOUT_SECONDS = 10.0
# Tests replace this with an httpx.MockTransport; None means the real network.
OIDC_HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None
OIDC_FAILURE_REDIRECT = "/?reason=oidc_failed"
# Asymmetric algorithms only: an HS* token must never be verified with a public key.
ID_TOKEN_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]


def _http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=OIDC_HTTP_TIMEOUT_SECONDS, transport=OIDC_HTTP_TRANSPORT
    )


def _secure_request(request: Request) -> bool:
    return (
        request.headers.get("x-forwarded-proto", "").lower() == "https"
        or request.url.scheme == "https"
    )


def _first_header_value(value: str | None) -> str:
    return (value or "").split(",", 1)[0].strip()


def _redirect_uri(request: Request) -> str:
    """Explicit OIDC_REDIRECT_URI, else PRESENTON_PUBLIC_URL, else the request origin."""
    configured = get_oidc_redirect_uri_env()
    if configured:
        return configured
    public_url = get_presenton_public_url()
    if public_url:
        return f"{public_url}{OIDC_CALLBACK_PATH}"
    scheme = _first_header_value(request.headers.get("x-forwarded-proto")) or request.url.scheme
    host = _first_header_value(request.headers.get("x-forwarded-host")) or request.headers.get("host", "")
    return f"{scheme}://{host}{OIDC_CALLBACK_PATH}"


def _scope_string() -> str:
    scopes = get_oidc_scopes().split()
    if "openid" not in scopes:
        scopes.insert(0, "openid")
    return " ".join(scopes)


def _require_oidc_config() -> tuple[str, str, str | None]:
    issuer = get_oidc_issuer_url()
    client_id = get_oidc_client_id()
    if not issuer or not client_id:
        logger.error("OIDC_ENABLED is true but OIDC_ISSUER_URL or OIDC_CLIENT_ID is not set")
        raise HTTPException(status_code=500, detail="OIDC sign-in is not configured")
    return issuer, client_id, get_oidc_client_secret()


async def _fetch_json(url: str) -> dict[str, Any]:
    async with _http_client() as client:
        response = await client.get(url)
        response.raise_for_status()
        document = response.json()
    if not isinstance(document, dict):
        raise ValueError("Expected a JSON object")
    return document


async def _fetch_discovery(issuer: str) -> dict[str, Any]:
    # Authentik's issuer ends with "/"; the discovery path is appended after stripping it.
    document = await _fetch_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
    required = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
    if not all(isinstance(document.get(key), str) and document.get(key) for key in required):
        raise ValueError("Discovery document is missing required endpoints")
    return document


def _oauth_client(client_id: str, client_secret: str | None, redirect_uri: str) -> AsyncOAuth2Client:
    return AsyncOAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scope=_scope_string(),
        token_endpoint_auth_method="client_secret_basic" if client_secret else "none",
        timeout=OIDC_HTTP_TIMEOUT_SECONDS,
        transport=OIDC_HTTP_TRANSPORT,
    )


def _validate_id_token(
    id_token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    client_id: str,
    nonce: str,
) -> dict[str, Any]:
    token = joserfc_jwt.decode(id_token, KeySet.import_key_set(jwks), algorithms=ID_TOKEN_ALGORITHMS)
    registry = JWTClaimsRegistry(
        iss={"essential": True, "value": issuer},
        aud={"essential": True, "value": client_id},
        exp={"essential": True},
        nonce={"essential": True, "value": nonce},
    )
    registry.validate(token.claims)
    return dict(token.claims)


def _encode_state_cookie(payload: dict[str, Any]) -> str:
    return jwt.encode(
        {**payload, "exp": int(time.time()) + OIDC_STATE_TTL_SECONDS},
        get_or_create_auth_secret(),
        algorithm="HS256",
    )


def _decode_state_cookie(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        return jwt.decode(token, get_or_create_auth_secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def _clear_state_cookie(response: RedirectResponse, request: Request) -> None:
    response.delete_cookie(
        OIDC_STATE_COOKIE_NAME,
        path=OIDC_COOKIE_PATH,
        httponly=True,
        secure=_secure_request(request),
        samesite="lax",
    )


def _clean_username(value: str) -> str:
    return re.sub(r"\s+", "_", value.strip())[:100]


async def _available_username(session: AsyncSession, preferred: str, subject: str) -> str:
    suffix = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:8]
    candidate = _clean_username(preferred)
    if len(candidate) < 3:
        candidate = f"user-{suffix}"
    taken = await session.scalar(
        select(User.id).where(func.lower(User.username) == candidate.casefold())
    )
    if taken is not None:
        candidate = f"{candidate[:91]}-{suffix}"
    return candidate


async def _get_or_create_oidc_user(
    session: AsyncSession, *, issuer: str, claims: dict[str, Any]
) -> User:
    subject = str(claims["sub"])
    oidc_subject = f"{issuer}#{subject}"
    admin_group = get_oidc_admin_group()
    groups = claims.get("groups")
    group_names = {str(group) for group in groups} if isinstance(groups, list) else set()

    user = await session.scalar(select(User).where(User.oidc_subject == oidc_subject))
    if user is None:
        preferred = (
            claims.get("preferred_username") or claims.get("email") or subject
        )
        if admin_group:
            is_admin = admin_group in group_names
        else:
            # Without an admin group, the first OIDC account on an instance with no
            # administrator becomes the administrator so admin-only features stay usable.
            has_admin = await session.scalar(
                select(exists().where(User.is_superuser.is_(True)))
            )
            is_admin = not has_admin
        user = User(
            username=await _available_username(session, str(preferred), subject),
            hashed_password=PASSWORD_HELPER.hash(secrets.token_urlsafe(32)),
            is_active=True,
            is_verified=True,
            is_superuser=is_admin,
            oidc_subject=oidc_subject,
            auth_version=1,
        )
        session.add(user)
    elif admin_group:
        user.is_superuser = admin_group in group_names
        session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@OIDC_ROUTER.get("/login")
async def oidc_login(request: Request):
    if not is_oidc_enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    issuer, client_id, client_secret = _require_oidc_config()
    try:
        discovery = await _fetch_discovery(issuer)
    except (httpx.HTTPError, ValueError) as exc:
        logger.error("OIDC discovery failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Identity provider is unavailable")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    redirect_uri = _redirect_uri(request)
    client = _oauth_client(client_id, client_secret, redirect_uri)
    authorization_url, _ = client.create_authorization_url(
        discovery["authorization_endpoint"],
        state=state,
        nonce=nonce,
        code_challenge=create_s256_code_challenge(code_verifier),
        code_challenge_method="S256",
    )

    response = RedirectResponse(authorization_url, status_code=302)
    response.set_cookie(
        OIDC_STATE_COOKIE_NAME,
        _encode_state_cookie(
            {
                "state": state,
                "nonce": nonce,
                "verifier": code_verifier,
                "redirect_uri": redirect_uri,
            }
        ),
        max_age=OIDC_STATE_TTL_SECONDS,
        httponly=True,
        secure=_secure_request(request),
        samesite="lax",
        path=OIDC_COOKIE_PATH,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@OIDC_ROUTER.get("/callback")
async def oidc_callback(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
):
    if not is_oidc_enabled():
        raise HTTPException(status_code=404, detail="Not Found")

    def failure(reason: str) -> RedirectResponse:
        logger.warning("OIDC sign-in rejected: %s", reason)
        response = RedirectResponse(OIDC_FAILURE_REDIRECT, status_code=302)
        _clear_state_cookie(response, request)
        return response

    if request.query_params.get("error"):
        return failure("identity provider returned an error")

    pending = _decode_state_cookie(request.cookies.get(OIDC_STATE_COOKIE_NAME))
    if pending is None:
        return failure("missing or expired state")
    if not secrets.compare_digest(
        str(pending.get("state", "")), request.query_params.get("state", "")
    ):
        return failure("state mismatch")
    code = request.query_params.get("code")
    if not code:
        return failure("missing authorization code")

    issuer, client_id, client_secret = _require_oidc_config()
    try:
        discovery = await _fetch_discovery(issuer)
        jwks = await _fetch_json(discovery["jwks_uri"])
        client = _oauth_client(client_id, client_secret, str(pending["redirect_uri"]))
        token = await client.fetch_token(
            discovery["token_endpoint"],
            grant_type="authorization_code",
            code=code,
            redirect_uri=str(pending["redirect_uri"]),
            code_verifier=str(pending["verifier"]),
        )
        claims = _validate_id_token(
            str(token["id_token"]),
            jwks,
            issuer=discovery["issuer"],
            client_id=client_id,
            nonce=str(pending["nonce"]),
        )
        if not claims.get("sub"):
            return failure("id token has no subject")
        user = await _get_or_create_oidc_user(
            session, issuer=discovery["issuer"], claims=claims
        )
    except (
        httpx.HTTPError,
        OAuthError,
        JoseError,
        IntegrityError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        await session.rollback()
        return failure(f"token exchange or validation failed ({type(exc).__name__})")

    if not user.is_active:
        return failure("account is inactive")

    session_token = await get_jwt_strategy().write_token(user)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=_secure_request(request),
        samesite="lax",
        path="/",
    )
    _clear_state_cookie(response, request)
    response.headers["Cache-Control"] = "no-store"
    return response
