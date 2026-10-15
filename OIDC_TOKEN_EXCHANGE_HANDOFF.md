# OIDC / RFC 8693 token-exchange auth for the LiteLLM proxy — handoff

Audience: a fresh Claude Code session started in a **clean clone** of `BerriAI/litellm`.
Goal: implement OIDC bearer auth for the proxy **as new open-source functionality**, with
**no dependence on the license-gated (enterprise) JWT surface**.

Everything below was verified on a working checkout on 2026-10-12/13, branch
`feat/oidc-jwt-rfc8693`. Line numbers are anchors, not contracts — re-grep before editing.

---

## 1. The requirement

An external service authenticates its own users with **EGI Check-in** (OIDC). That service
performs an **RFC 8693 token exchange** and then calls this LiteLLM proxy **on the user's
behalf**, carrying the exchanged access token as a bearer token in `Authorization`.

- This proxy is registered at EGI Check-in as a service (a client), so the exchanged token's
  `aud` is this proxy's own `client_id`.
- `sub` identifies the **delegated human user**; `act.sub` identifies the **calling service**
  (RFC 8693 actor).
- On a valid token the proxy must **validate it**, then look the user up in its DB. If absent,
  **create exactly one user record per external identity**, so budgets, rate limits and any
  other policy can be applied to that identity.

Decisions already taken with the requester:

| Question | Decision |
|---|---|
| What identifies the user? | `sub` = user, `act.sub` = calling service |
| Upstreamable? | Yes — this must be a contribution that upstream would plausibly accept |
| How is the token presented? | `Authorization: Bearer <jwt>`; existing virtual keys must keep working, so fallthrough behavior is runtime-configurable in **4 modes** |
| Where does it live? | A **new standalone path**, not bolted onto the enterprise JWT branch |
| Provisioning | Upsert the user **and** optionally mint a virtual key |
| Scope | Uniform across all proxy routes that accept a bearer |

Final explicit constraint from the requester (drives everything in §3):

> "Focus on the recommended way, i.e. building new OSS functionality, as independent on the
> behind-the-gate code as possible."

---

## 2. What exists in the repo today (verified)

### 2.1 OIDC / RFC 8693 facts for EGI Check-in

| Item | Value |
|---|---|
| Issuer (`iss`) | `https://aai.egi.eu/auth/realms/egi` |
| JWKS | `https://aai.egi.eu/auth/realms/egi/protocol/openid-connect/certs` |
| Discovery | `https://aai.egi.eu/auth/realms/egi/.well-known/openid-configuration` (has `jwks_uri`) |
| Algorithm | RS256 |
| `sub` | Community User Identifier, e.g. `<uuid>@egi.eu` |
| `act` | `{"sub": "<calling service>"}` — RFC 8693 actor claim |
| `aud` | this proxy's `client_id` at EGI Check-in |
| Token type | `urn:ietf:params:oauth:token-type:access_token` (RFC 8693 §2.2.1 `token_type`) |

Do **not** hardcode EGI specifics beyond documentation examples — the config must be generic
(any OIDC issuer), with EGI Check-in as the motivating deployment.

### 2.2 Generic (MIT-licensed) pieces a standalone path may legitimately reuse

Everything outside `enterprise/` is MIT (see `LICENSE`; the commercial gate is the
`enterprise/` directory only). These are plain primitives, not the gated feature:

| Primitive | Location (approx.) | Notes |
|---|---|---|
| JWT parsing / signing dep | `pyproject.toml` — `PyJWT>=2.13.0,<3.0`, `cryptography>=49` | already installed; `jwt.PyJWKClient` is available (verified `jwt` 2.15.0) |
| JWT validation (iss/aud/exp/nbf, JWKS fetch + cache) | `litellm/proxy/auth/handle_jwt.py` → `JWTHandler.auth_jwt` (~1379), `_get_public_key_from_jwks_url` (~1024), `_resolve_jwks_url` (~822) | **biggest reuse win** — JWKS is fetched through `user_api_key_cache` with single-flight refresh locks |
| JWT shape test | `JWTHandler.is_jwt` (`handle_jwt.py` ~287) | static, `len(token.split(".")) == 3` |
| Per-issuer config model | `JWTIssuerConfig` (`_types.py` ~5320) | already supports `jwks_url`, audience, claim mappings |
| User lookup + JIT upsert | `get_user_object(..., user_id_upsert=bool, ...)` (`proxy/auth/auth_checks.py` ~2725) | applies `litellm.default_internal_user_params` (budget/duration/role) on create — exactly the "one record per identity with policies" requirement |
| Virtual-key lookup | `get_key_object(...)` (`proxy/auth/auth_checks.py` ~4007) | returns a fully-populated `UserAPIKeyAuth` including team grants |
| Virtual-key minting from a validated identity | `_auto_register_jwt_mapping` (`user_api_key_auth.py` ~969) | accepts `virtual_key_claim_field`, `claim_value`, `user_id`, `team_id`, … and calls `generate_key_helper_fn` |
| Key generation primitive | `generate_key_helper_fn` (`proxy/management_endpoints/key_management_endpoints.py` ~4558) | the same helper OSS `/key/generate` uses |
| Auth result type | `UserAPIKeyAuth` (`_types.py` ~3416) | the contract `user_api_key_auth` must return |

`get_user_object` and `get_key_object` are **not** license-gated (verified: no `premium_user`
reference in `handle_jwt.py`, none in the `get_user_object` upsert block).

### 2.3 What is gated

`litellm/proxy/auth/user_api_key_auth.py` (~1729 in the current WIP) contains:

```python
if not (_jwt_is_oidc or premium_user is True):
    raise ProxyException(... "JWT Auth is an enterprise only feature" ...)
```

The whole enterprise JWT surface hangs off this: `enable_jwt_auth` in `general_settings`
implies a license, and `JWTAuthManager.auth_builder` (`handle_jwt.py` ~2488) layers on admin
scope mapping, team mapping, `virtual_key_claim_field` mapping, `unregistered_jwt_client_behavior`
(auto-register / reject), `oidc_userinfo`, custom validators, etc.

---

## 3. Recommended approach: a standalone OSS OIDC path

**Do not** relax, duck around, or parameterize the `premium_user` check, and **do not** route
OIDC tokens through `auth_builder`. The previous attempt on `feat/oidc-jwt-rfc8693` did exactly
that (see §5) and was rejected as a licensing hack: it makes an OSS feature depend on a
commercial one, conflates a narrow token-exchange feature with the broad enterprise JWT
surface, and upstream maintainers would read it as monetization leakage.

Instead: a **self-contained module** that shares only §2.2 primitives, enabled by its own
config key, gated by nothing.

### 3.1 New module: `litellm/proxy/auth/oidc_token_exchange.py`

```python
class OIDCTokenExchangeAuthenticator:
    """RFC 8693 token-exchange bearer auth. Open source; no license gate."""

    def __init__(self, config: OIDCTokenExchangeConfig, *, jwks: JWKSVerifier) -> None: ...

    async def authenticate(
        self, *, token: str, prisma_client, user_api_key_cache,
        proxy_logging_obj, parent_otel_span, request,
    ) -> UserAPIKeyAuth: ...
```

Split the verification so it is unit-testable without a proxy:

- `JWKSVerifier` (thin wrapper): `async verify(token, *, issuer, audience, leeway) -> dict`
  — decodes the header for `kid`, fetches/caches the JWKS, checks signature + `iss` + `aud` +
  `exp`/`nbf`, raises a typed error. **Reuse `JWTHandler`'s JWKS fetch/cache internals rather
  than reimplementing them**, either by extracting them into a small shared helper (preferred,
  upstream-friendly) or by calling the existing `_get_public_key_from_jwks_url` /
  `_resolve_jwks_url` methods. Extracting is the better PR: it leaves `handle_jwt.py` behavior
  identical while making the cache reusable.
- `resolve_identity(claims) -> OIDCIdentity(user_id, email, actor)` — reads the configured
  `subject_jwt_field` (default `sub`, dot-notation) and `actor_jwt_field` (default `act.sub`).

Sequence inside `authenticate`:

1. `claims = await verifier.verify(token, issuer=cfg.issuer, audience=cfg.audience)`.
2. `identity = resolve_identity(claims)` — reject (401) if the subject claim is empty.
3. `user = await get_user_object(user_id=identity.user_id, prisma_client=…, user_api_key_cache=…, user_id_upsert=cfg.upsert_user, user_email=identity.email, parent_otel_span=…, proxy_logging_obj=…)`.
   This is the "one user record per external identity" step, and it applies
   `litellm.default_internal_user_params` for limits on create.
4. If `cfg.auto_register_virtual_key`: mint/lookup a key via `_auto_register_jwt_mapping`
   with `claim_field=cfg.subject_jwt_field`, `claim_value=identity.user_id`, `user_id=…`
   (this mirrors what the enterprise auto-register does, using only MIT helpers).
5. Build and return `UserAPIKeyAuth(user_id=…, user_email=…, user_role=LitellmUserRoles.INTERNAL_USER, jwt_claims=claims, user_tpm_limit=user.tpm_limit, user_rpm_limit=user.rpm_limit, user_model_max_budget=user.model_max_budget, parent_otel_span=…)`.
   Mirror the field set of `JWTAuthManager.user_api_key_auth_from_result` (`handle_jwt.py` ~3038)
   so downstream budget/limit enforcement sees the same shape — but write it in the new module;
   do not call that method.

Record the actor for attribution: put badged actor info in `jwt_claims` under a documented
internal key (e.g. `_litellm_jwt_actor`) or in a new `UserAPIKeyAuth` field, so spend logs and
callbacks can attribute the *calling service*. Keep it out of any code path the enterprise
branch reads.

### 3.2 Config surface (new, additive, in `litellm/proxy/_types.py`)

Reuse the shape already designed on the WIP branch — it was fine; only the wiring was wrong:

```python
class AuthOrder(str, enum.Enum):
    VIRTUAL_KEY_THEN_JWT = "virtual_key_then_jwt"   # default; backwards compatible
    JWT_THEN_VIRTUAL_KEY = "jwt_then_virtual_key"
    JWT_ONLY = "jwt_only"
    VIRTUAL_KEY_ONLY = "virtual_key_only"

class OIDCTokenExchangeConfig(LiteLLMPydanticObjectBase):
    issuer: str                      # exact expected `iss`
    jwks_url: str | None = None      # else resolved via OIDC discovery from issuer
    audience: str | list[str]        # this proxy's client_id
    subject_jwt_field: str = "sub"
    actor_jwt_field: str = "act.sub"
    upsert_user: bool = True
    auto_register_virtual_key: bool = False

class LiteLLM_JWTAuth(...):   # existing model — additive fields only
    oidc_enabled: bool = False
    oidc_token_exchange: OIDCTokenExchangeConfig | None = None
    auth_order: AuthOrder = AuthOrder.VIRTUAL_KEY_THEN_JWT
```

Validation: `oidc_enabled=True` with `oidc_token_exchange is None` must raise at model
construction (fail fast at startup, not per request).

**Design question worth raising with the requester before coding:** should this hang off
`general_settings.litellm_jwtauth` at all, given that name is entangled with the enterprise
feature? A neutral top-level key — e.g. `general_settings.oidc_token_exchange:` — is cleaner
for an OSS-only feature and reads better in an upstream PR. The WIP branch used the nested
form; the `auth_order` / `oidc_*` fields are trivially relocatable either way. Decide this
first; it changes the config docs and the tests but nothing structural.

### 3.3 Wiring into `_user_api_key_auth_builder` (`user_api_key_auth.py` ~1518)

Inserts **before** the existing `#### IF JWT ####` block, and — critically — the OIDC branch
**returns**, so none of the enterprise code below is reached:

```python
# open-source OIDC / RFC 8693 token-exchange
_oidc_cfg = _get_oidc_config(general_settings)       # None when disabled
_oidc_requested = _oidc_cfg is not None and jwt_handler.is_jwt(token=api_key)

if _oidc_requested and _oidc_order in (JWT_ONLY, JWT_THEN_VIRTUAL_KEY):
    return await _oidc_authenticator().authenticate(token=api_key, ...)

# later, in the existing virtual-key path, only when order is
# VIRTUAL_KEY_THEN_JWT and the bearer is JWT-shaped and no key matched:
if _oidc_requested and _oidc_order is VIRTUAL_KEY_THEN_JWT and key_lookup_failed:
    return await _oidc_authenticator().authenticate(token=api_key, ...)
```

Rules to preserve:

- `VIRTUAL_KEY_THEN_JWT` (default): a bearer that resolves as a virtual key or master key is
  used as today; a JWT-shaped bearer that matches no key falls to OIDC.
- `JWT_THEN_VIRTUAL_KEY`: a JWT-shaped bearer is validated as OIDC **first**; a JWT that fails
  validation is **401** — never silently retried as a virtual key. A non-JWT bearer goes to
  the existing key path.
- `JWT_ONLY`: non-JWT bearer → 401; this makes the `master_key` not work as a bearer, which is
  intended (verified in the live E2E).
- `VIRTUAL_KEY_ONLY`: OIDC JWTs are never authenticated — the request falls into the normal
  key path, and a JWT-shaped bearer simply fails as an unknown key. **No `premium_user`
  check, no enterprise error message**: this is OSS behavior identical to a build without the
  feature.

`oidc_enabled` must **not** set `general_settings.enable_jwt_auth`. That was the mistake in §5.

### 3.4 What must stay untouched

- `litellm/proxy/auth/handle_jwt.py` — the `JWTAuthManager` / `auth_builder` / premium
  machinery. Extract the JWKS helper only if you extract it cleanly (§3.1); do not add OIDC
  branches inside `auth_builder`, `auth_jwt`, `is_upsert_user_id`, `_get_effective_issuers`,
  `_apply_issuer_claim_mappings`, etc.
- The `premium_user` check in `user_api_key_auth.py`. Not one character changes.
- `LiteLLM_JWTAuth`'s existing defaults and meaning for enterprise deployments. Only additive
  fields (§3.2) — and per §3.2 consider not touching this model at all.
- Budget JSON files (`ruff-strict-budget.json`, `type-discipline-budget.json`,
  `basedpyright-code-budget.json`, `test-quality-budget.json`) — ratcheted by CI on the default
  branch; never edit on a PR branch.

### 3.5 Tests

`tests/unit/proxy/auth/test_oidc_token_exchange.py` — mocked only, no network (repo rule).
Cover at minimum:

- config validation (`oidc_enabled` without `oidc_token_exchange` raises; defaults)
- concerning the token: valid RS256 token validates and maps `sub` → `user_id`, `act.sub` → actor
- wrong `aud` → rejected ("Audience doesn't match" style message)
- wrong `iss` → rejected (must not fall back to any permissive path)
- expired token → rejected; missing `act` → actor is `None`, not an error
- `upsert_user=True` → `get_user_object` called with `user_id_upsert=True`; `False` → not
  called for a missing user / raises
- repeat request → same user id, no second insert (call-count assertion on the mocked repo)
- all four `auth_order` values: which branch handles a JWT bearer, and that
  `VIRTUAL_KEY_ONLY` never invokes the OIDC authenticator
- `premium_user is False` → the OIDC path still works, **and** a non-OIDC JWT still gets the
  enterprise 403 (this is the test that pins the license boundary)

Generate RSA keypairs in-process (`cryptography`, already a dep) and monkeypatch the JWKS
fetch. The WIP branch's fixture `rsa_keypair` and its `monkeypatch`-based setup are a usable
starting point; adapt the call sites to the new module.

`tests/llm_translation/` is not relevant. Consider one `tests/e2e/` case later; follow
`tests/e2e/AGENTS.md` strictly (shared transport, `Result` unions, `@pytest.mark.covers`, no
mocking of product code).

---

## 4. Verifying locally, end to end

The throwaway harness from the previous session is still on disk at `/tmp/oidc-e2e/` and was
verified working against the WIP branch. It is exactly what a standalone module should also
pass — reuse it, adjust only the config key if §3.2 changes it.

- **`/tmp/oidc-e2e/jwks_server.py`** — generates an RSA keypair, persists
  `/tmp/oidc-e2e/private_key.pem`, serves the public key at `http://127.0.0.1:8787/jwks.json`.
  Run: `uv run --project <repo> python /tmp/oidc-e2e/jwks_server.py`
- **`/tmp/oidc-e2e/mint_token.py`** — mints an RFC 8693-shaped token.
  `uv run --project <repo> python /tmp/oidc-e2e/mint_token.py [sub] [aud] [iss] [act_sub]`;
  defaults: `alice-external@egi.eu`, `local-proxy-client-id`, `http://127.0.0.1:8787`,
  `external-service`.
- **`/tmp/oidc-e2e/proxy_oidc_config.yaml`** — reference config: `oidc_enabled: true`,
  `auth_order: "jwt_only"`, issuer/jwks/audience, `upsert_user: true`,
  `auto_register_virtual_key: true`, plus `default_internal_user_params` (budget/duration/role)
  so the JIT-provisioned user inherits real limits.
- Start the proxy as in the memory below, then:
  `TOKEN=$(uv run --project <repo> python /tmp/oidc-e2e/mint_token.py)` and
  `curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4000/v1/chat/completions -d '{...}'`.

**Expected results (all verified on the WIP branch):** first call authenticates and creates
exactly one `LiteLLM_UserTable` row for the external identity; a repeat call reuses it; wrong
`aud` → 401 with an audience-mismatch message; `jwt_only` rejects the master key as a bearer.
On the standalone design, add: with `premium_user` false, OIDC still works and a non-OIDC JWT
is still refused.

Local stack basics (Postgres container, `.env`, ports, test keys) are in the agent memory
file `local-test-env-einfra.md` — read it rather than rebuilding:

- Postgres 16 container `litellm-test-postgres` on `127.0.0.1:5432`, user/pass/db `litellm`
- repo-root `.env` (gitignored) supplies `LITELLM_EINFRA_API_KEY`, `LITELLM_MASTER_KEY`,
  `DATABASE_URL`; the upstream is `https://llm.ai.e-infra.cz/v1`
- proxy: `uv run litellm --config <config> --host 127.0.0.1 --port 4000 --detailed_debug`

### Security constraints — carry these forward

- `--host 127.0.0.1` is **mandatory**; the default is `0.0.0.0`, which would expose the proxy.
- Never commit the throwaway configs (`litellm/proxy/local_test_config.yaml`,
  `/tmp/oidc-e2e/proxy_oidc_config.yaml`) or `.env`. The local config is kept out of git via
  `.git/info/exclude`.
- Never commit `/tmp/oidc-e2e/private_key.pem` anywhere, and never point a real deployment at
  that JWKS server.
- An OIDC-authenticated caller is not a proxy admin: return `INTERNAL_USER` and let the
  normal budget/rate-limit checks apply.

---

## 5. The rejected approach (on branch `feat/oidc-jwt-rfc8693`)

Kept here so a fresh session does not repeat it. The branch sits on
`e1bdd42726` (= `origin/main` at the time) with two commits:

- `640ff535a3 feat(proxy): open-source OIDC / RFC 8693 token-exchange JWT auth`
  — `_types.py` (+80), `handle_jwt.py` (+104), `user_api_key_auth.py` (+57),
  `tests/unit/proxy/auth/test_oidc_token_exchange.py` (+213).
- `2a2f6b7d69 fix(proxy): route OIDC upsert_user default through auth_builder provisioning`
  — `handle_jwt.py` (+10), a follow-up to make JIT provisioning actually fire.

What it did, and why each is wrong:

1. **Softened the license gate** in `user_api_key_auth.py`:
   `if not (_jwt_is_oidc or premium_user is True): raise ...`. Lawful (the flag lives in MIT
   code; only `enterprise/` is commercial) but it makes an OSS feature depend on a commercial
   one and is exactly the kind of change upstream rejects. **Drop this entirely.**
2. **Made `oidc_enabled` imply `enable_jwt_auth`**, funnelling OIDC tokens through the
   enterprise `auth_builder` (`handle_jwt.py` ~2488) — so the OSS feature only worked by
   running the premium code path with the gate propped open. **Drop this entirely.**
3. **Extended enterprise internals for OIDC**: a `LITELLM_JWT_ACTOR_CLAIM`, actor stamping
   inside `_apply_issuer_claim_mappings`, OIDC folded into `_get_effective_issuers`,
   `_is_oidc_issuer`, `is_upsert_user_id` returning True for `oidc_token_exchange.upsert_user`,
   and the `auth_builder` provisioning change in `2a2f6b7d69`. This is the entanglement to
   avoid; put the equivalent logic in the new module.
4. **Needed a hard 401 for issuer mismatch in `auth_jwt`** to stop the permissive
   no-audience fallback from accepting unrelated issuers. A standalone verifier that always
   checks `iss` + `aud` has no such hole, so this hardening becomes unnecessary.

Genuinely reusable from that branch: the `AuthOrder` enum, the `OIDCTokenExchangeConfig`
model (name, fields, defaults — §3.2), and the shape of the 10 unit tests. The `rsa_keypair`
fixture and the monkeypatch scaffolding in
`tests/unit/proxy/auth/test_oidc_token_exchange.py` are worth salvaging too.

Repo state to expect: branch `feat/oidc-jwt-rfc8693`, `CLAUDE.md` untracked, temp services may
still be running (proxy on `:4000` with the OIDC config, JWKS on `:8787`, the Postgres
container).

---

## 6. Suggested order of work

1. Settle §3.2's placement question (nested under `litellm_jwtauth` vs. a neutral top-level
   `general_settings.oidc_token_exchange`).
2. `OIDCTokenExchangeConfig` + `AuthOrder` in `_types.py`, with the fail-fast validation.
3. Extract the JWKS fetch/cache helper from `JWTHandler` into a shared, behavior-preserving
   utility; run the existing JWT unit tests to prove no behavior change.
4. Write `litellm/proxy/auth/oidc_token_exchange.py` (§3.1) and its unit tests
   (`tests/unit/proxy/auth/test_oidc_token_exchange.py`).
5. Wire the four `auth_order` modes into `_user_api_key_auth_builder` (§3.3). No other file.
6. Run the full local E2E (§4) and the license-boundary test from §3.5.
7. `make format`, `make lint-dev`, then the targeted unit run — see `CLAUDE.md` and the
   `AGENTS.md` files for the exact commands and the PR/commit conventions they impose.
8. Only then consider a PR: docs for the new config key, and a short note in the PR body that
   the feature is OSS and deliberately independent of `premium_user`.
