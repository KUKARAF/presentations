# OpenID Connect sign-in with Authentik

This guide sets up Presenton so that every user who can authenticate in an
Authentik instance can sign in to Presenton. It is written so an AI agent or an
operator can follow it end to end. Items marked "verify in your Authentik
version" were not checked against a specific Authentik release.

## How it works

- Sign-in uses the OpenID Connect authorization code flow with PKCE (S256),
  plus `state` and `nonce` validation. The ID token is checked for signature
  (RS256/ES256/PS256 families only), `iss`, `aud`, `exp`, and `nonce`.
- After a successful sign-in Presenton issues its normal session cookie
  (`presenton_session`, HTTP-only, `SameSite=Lax`). Every existing session check
  (the Next.js proxy, the FastAPI middleware, the admin checks) keeps working
  unchanged.
- Presenton creates a local user row on first sign-in, keyed by
  `<issuer>#<sub>`. Later sign-ins reuse that row.
- Access policy is not enforced by Presenton. Anyone Authentik lets into the
  Presenton application can sign in. Control access in Authentik (see below).
- When OIDC is enabled, local username/password sign-in (`/setup` and `/login`)
  is disabled, so Authentik is the only way in.
- Logging out clears the Presenton session only. The Authentik session stays
  active, so signing in again is one click at the identity provider.

## Environment variables

Set these in the environment of the Presenton container, or in the `.env` file
next to `docker-compose.yml` (Docker Compose reads it automatically).

| Variable | Required | Default | Meaning | Example |
|---|---|---|---|---|
| `OIDC_ENABLED` | yes, to turn it on | `false` | Enables OIDC sign-in and disables local password sign-in. With `false` the upstream behavior is unchanged. | `true` |
| `OIDC_ISSUER_URL` | yes when enabled | none | Issuer of the Authentik OAuth2/OpenID provider. Presenton appends `/.well-known/openid-configuration` to it. | `https://authentik.example.com/application/o/presenton/` |
| `OIDC_CLIENT_ID` | yes when enabled | none | Client ID from the Authentik provider. | `aB3...` (copied from Authentik) |
| `OIDC_CLIENT_SECRET` | recommended | none | Client secret from the Authentik provider (confidential client, sent with HTTP Basic auth). If empty, the token request uses no client authentication, which only works for a public client. | `long-random-secret` |
| `OIDC_REDIRECT_URI` | recommended | derived | Callback URL registered in Authentik. If unset, it is `PRESENTON_PUBLIC_URL` + `/api/v1/auth/oidc/callback`; if that is also unset, it is built from the `X-Forwarded-Proto` / `X-Forwarded-Host` headers (or `Host`). Set it explicitly in production. | `https://presenton.example.com/api/v1/auth/oidc/callback` |
| `OIDC_SCOPES` | no | `openid profile email` | Space-separated scopes. `openid` is added automatically if missing. | `openid profile email groups` |
| `OIDC_ADMIN_GROUP` | no | none | If set, a user is an admin exactly when the `groups` claim contains this group name, re-checked on every sign-in. If unset, see "Administrator role" below. | `presenton-admins` |
| `PRESENTON_PUBLIC_URL` | used for the default redirect URI | empty | Public URL of Presenton, without a trailing slash. Already passed through by `docker-compose.yml`. | `https://presenton.example.com` |
| `USER_CONFIG_PATH` | must already be set | set in Docker | Presenton stores its session signing key (`AUTH_SECRET_KEY`) in this file. OIDC uses that same key to sign the short-lived login-state cookie, so no separate `SESSION_SECRET` is needed. | `/app_data/userConfig.json` |

Notes:

- There is no `SESSION_SECRET` variable. The existing `AUTH_SECRET_KEY`
  (generated and persisted in `USER_CONFIG_PATH`) is reused.
- Changing `OIDC_ENABLED` takes effect after a container restart.
- Presenton fetches the discovery document, the JWKS, and the token endpoint
  from the Presenton server itself. In Docker, `OIDC_ISSUER_URL` must be
  reachable from inside the container, not only from your browser.

### Administrator role

- Without `OIDC_ADMIN_GROUP`: the first OIDC account created on an instance
  that has no administrator becomes an administrator. Later OIDC accounts are
  regular users. Administrator-only features are unavailable to regular users.
- With `OIDC_ADMIN_GROUP`: the role is synced from the `groups` claim on every
  sign-in. The `groups` claim must be present in the ID token (see Authentik
  step 4).

## Authentik configuration

Menu names and field labels change between Authentik versions. Verify them in
your version.

1. **Create a provider.** In the admin interface, go to Applications, then
   Providers, and create an OAuth2/OpenID Provider.
   - Client type: **Confidential**. This gives you a client ID and client
     secret, which map to `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.
   - Authorization flow: an authorization flow that allows the
     authorization code grant (for example the default implicit-consent
     flow). Verify in your version.
   - Redirect URIs (strict match): add exactly
     `https://<your-presenton-host>/api/v1/auth/oidc/callback`. For local
     Docker use `http://localhost:5001/api/v1/auth/oidc/callback`, adjusted to
     `PRESENTON_HTTP_HOST_PORT`. The value must equal `OIDC_REDIRECT_URI`
     character for character: scheme, host, port, path, and no trailing slash.
   - Signing key: select a signing certificate/key so the ID token is signed
     with RS256. Verify in your version. Presenton accepts RS256, RS384, RS512,
     PS*, and ES* signatures.
   - Scopes: include `openid`, `profile`, and `email`. Add a scope mapping that
     returns a `groups` claim only if you use `OIDC_ADMIN_GROUP`. Verify that
     the `groups` claim appears in the ID token in your version.
   - PKCE: Presenton always sends PKCE (`code_challenge_method=S256`). Verify
     in your version that the provider accepts it. Enabling PKCE on the
     provider is recommended.
2. **Note the issuer.** Authentik shows the OpenID configuration URL for the
   provider. It has the form
   `https://<authentik-host>/application/o/<application-slug>/.well-known/openid-configuration`.
   Remove the `/.well-known/openid-configuration` suffix and keep the trailing
   slash. This is `OIDC_ISSUER_URL`, for example
   `https://authentik.example.com/application/o/presenton/`.
   The application slug is the value you enter in step 3.
3. **Create an application.** Create an Application, set a name and a slug
   (the slug becomes part of the issuer URL above), and select the provider
   from step 1 as the provider.
4. **Let all users in.** Presenton does not check groups or emails, so
   Authentik decides who gets in. In Authentik, an application with no policy,
   group, or user bindings is accessible to any user who can log in to
   Authentik. Verify this in your version. To restrict access instead, add
   bindings (policies, groups, or users) to the application. Users who fail
   the bindings never reach Presenton. Do not bind to a group unless that is
   the intent.
5. **Copy the values** into the Presenton environment: client ID, client
   secret, issuer URL (from step 2), and the redirect URI from step 1.

## Running locally with Docker Compose

`docker-compose.yml` passes the OIDC variables through to the `production`,
`production-gpu`, `development`, and `development-gpu` services. Add the
values to `.env` in the repository root (this file is git-ignored):

```bash
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://authentik.example.com/application/o/presenton/
OIDC_CLIENT_ID=<client id from Authentik>
OIDC_CLIENT_SECRET=<client secret from Authentik>
OIDC_REDIRECT_URI=http://localhost:5001/api/v1/auth/oidc/callback
PRESENTON_PUBLIC_URL=http://localhost:5001
```

Then start the service:

```bash
docker compose up -d --build production
```

The app is on `http://localhost:${PRESENTON_HTTP_HOST_PORT:-5001}`. Use the
same host in `PRESENTON_PUBLIC_URL`, `OIDC_REDIRECT_URI`, and the redirect URI
registered in Authentik.

Authentik must be reachable from inside the Presenton container at
`OIDC_ISSUER_URL`. Self-signed or private CA certificates are not configured by
this change. If Authentik uses one, the token and discovery requests will fail.

## Verification

Replace the placeholder values with your own.

### 1. Discovery document (Authentik side)

```bash
curl -s "https://authentik.example.com/application/o/presenton/.well-known/openid-configuration" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["issuer"]); print(d["authorization_endpoint"]); print(d["token_endpoint"]); print(d["jwks_uri"])'
```

The printed `issuer` should be the same value as `OIDC_ISSUER_URL` (with the
trailing slash). Presenton uses the issuer from this document for validation.

### 2. Presenton status

```bash
curl -s http://localhost:5001/api/v1/auth/status
# {"configured":true,"authenticated":false,"username":null,"user_id":null,"role":null,"oidc_enabled":true}
```

`oidc_enabled` must be `true` and `configured` must be `true`.

### 3. Entry point redirects to the identity provider

```bash
curl -s -o /dev/null -D - http://localhost:5001/api/v1/auth/oidc/login | grep -i '^location'
```

The `Location` header must point at the `authorization_endpoint`, and its
query must contain `redirect_uri=` (URL-encoded, matching the redirect URI
registered in Authentik), `code_challenge_method=S256`, `state`, and `nonce`.
The response also sets the short-lived `presenton_oidc_state` cookie.

### 4. Protected API is closed without a session

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5001/api/v1/auth/verify
# 401
```

### 5. Browser smoke test

1. Open `http://localhost:5001/` in a fresh private window. The sign-in page
   must show "Sign in with Authentik" and no username/password form.
2. Click the button. You should land on the Authentik sign-in page.
3. Sign in with a user that is allowed by the application bindings.
4. You should be redirected back to Presenton and see the workspace.
5. Check the session:
   ```bash
   curl -s -b cookies.txt http://localhost:5001/api/v1/auth/status
   ```
   Use cookies saved from the browser, or sign in and save the cookie with
   `curl -c cookies.txt`. The response must show `"authenticated":true` and the
   Authentik username (`preferred_username`, falling back to `email` and then
   `sub`).
6. Click Logout. Then `curl -s -o /dev/null -w '%{http_code}\n' -b cookies.txt http://localhost:5001/api/v1/auth/verify` must print `401`.
7. Sign in with a user that is not allowed by the bindings. Authentik should
   refuse, and Presenton must not create a session.

## Troubleshooting

**Authentik shows a redirect URI error (mismatch or invalid).**
The `redirect_uri` in the URL from `/api/v1/auth/oidc/login` must match a
Redirect URI registered in Authentik exactly. Check scheme (`http` vs `https`),
host, port, and path. Remove any trailing slash. Behind a reverse proxy, the
host Presenton sees may differ from the public host. Set `OIDC_REDIRECT_URI`
explicitly to avoid this.

**Issuer mismatch or wrong discovery document.**
Presenton builds the discovery URL from `OIDC_ISSUER_URL` by stripping one
trailing `/` and appending `/.well-known/openid-configuration`, so the value
with or without the trailing slash resolves to the same URL. Presenton then
checks the token's `iss` against the `issuer` field in the discovery document,
not against the environment variable, so a trailing-slash difference does not
break validation. The real mistakes are a wrong application slug, or an issuer
taken from a different provider, which points the discovery URL at the wrong
application. Verify with step 1 of the verification section. If your Authentik
version offers both per-provider and global issuers, use the one its discovery
document reports. Verify in your version.

**Sign-in returns to the login page with the "Sign-in failed" message.**
The reason is logged by the Presenton server as `OIDC sign-in rejected: <reason>`.
Common reasons:
- `missing or expired state`: the state cookie was lost or older than 10
  minutes. Start again from the login button. If it happens every time, see
  the cookie notes below.
- `state mismatch`: the callback was opened in another browser or the state
  cookie was blocked.
- `token exchange or validation failed (...)`: check the exception name in the
  log. A `OAuthError` usually means a wrong client ID or secret, or the wrong
  redirect URI. An `InvalidClaimError` for `nonce` or `iss` usually means the
  issuer or the provider configuration is wrong. Check `OIDC_CLIENT_SECRET`
  against Authentik.
- `account is inactive`: the Presenton user row was deactivated. Presenton does
  not expose user deactivation through OIDC; change `is_active` in the database.

**HTTP 502 "Identity provider is unavailable" on the login button.**
The Presenton server could not fetch the discovery document. Check that
`OIDC_ISSUER_URL` is reachable from inside the container, that DNS resolves,
and that TLS is trusted (see the note on certificates above).

**HTTP 500 "OIDC sign-in is not configured".**
`OIDC_ISSUER_URL` or `OIDC_CLIENT_ID` is empty while `OIDC_ENABLED=true`.

**Secure cookies behind an HTTPS reverse proxy.**
The session and state cookies get the `Secure` flag when the request is HTTPS
or `X-Forwarded-Proto: https` is present. The bundled `nginx.conf` forwards
`X-Forwarded-Proto` and `X-Forwarded-Host`. If you put another proxy in front
(Traefik, Caddy, a cloud load balancer), make sure it sets
`X-Forwarded-Proto` to the scheme the browser used.
- If the public site is HTTPS but the proxy does not send
  `X-Forwarded-Proto: https`, cookies are issued without `Secure`. Sign-in
  still works, but the flag is missing.
- If the browser uses plain HTTP (for example `http://localhost`) while
  `X-Forwarded-Proto` says `https`, browsers drop the `Secure` cookies. The
  result is a loop back to the login page after a successful Authentik sign-in.
  Fix the proxy header, or access the app over HTTPS.

**"Local sign-in is disabled" (HTTP 403 on `/api/v1/auth/login`).**
Expected while `OIDC_ENABLED=true`. Set `OIDC_ENABLED=false` to return to
local accounts.

**Administrator features are missing.**
Check whether an administrator exists. Without `OIDC_ADMIN_GROUP`, only the
first OIDC account on an instance with no administrator is promoted. With
`OIDC_ADMIN_GROUP`, confirm that the `groups` claim contains that exact group
name (case-sensitive) and that the scope mapping returns it.

**The login button is missing and the password form appears.**
The frontend has not read `oidc_enabled=true`. Check the status endpoint
(verification step 2) and confirm the container was restarted after changing
the environment.
