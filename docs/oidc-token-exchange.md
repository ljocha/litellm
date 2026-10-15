# OIDC token-exchange authentication (open source)

Authenticate callers presenting an OIDC bearer token (including RFC 8693
token-exchange tokens) without an enterprise license. This is a standalone
auth path, separate from the enterprise `litellm_jwtauth` feature: OIDC-issuer
tokens authenticate through it while other JWTs still need the enterprise
feature.

In a token-exchange flow, `sub` identifies the delegated human user and
`act.sub` the calling service. One human maps to exactly one proxy user
record, so budgets and rate limits apply per person regardless of which
service exchanged the token. The full claims, including `act`, are attached to
the request for attribution. An OIDC-authenticated caller is an internal
user, never a proxy admin.

## Configuration

Enable under `general_settings.oidc_token_exchange`:

```yaml
general_settings:
  oidc_token_exchange:
    issuer: https://aai.egi.eu/auth/realms/egi
    audience: my-litellm-proxy
```

Malformed config fails fast at startup with the offending field named; a
proxy without the key boots unchanged.

| field | type | default | meaning |
| --- | --- | --- | --- |
| `issuer` | str | required | Exact expected `iss` claim of accepted tokens |
| `audience` | str or list[str] | required | This proxy's client id(s); token accepted when `aud` intersects |
| `jwks_url` | str | none | Explicit JWKS endpoint; when absent, resolved via OIDC discovery from the issuer |
| `upsert_user` | bool | `true` | Find-or-create one proxy user record per `sub`; `false` rejects unknown identities with 403 |
| `auto_register_virtual_key` | bool | `false` | Mint a virtual key owned by the provisioned user on first authentication, so the human can call the proxy directly |
| `jwks_cache_ttl` | float | `600` | Seconds a fetched JWKS is reused before re-fetching |

Token validation enforces the signature against the issuer's published keys
(algorithm taken from the JWKS key entry, never the token header), exact
issuer, audience match, and expiry. Rejections return 401 with a
one-sentence reason.

## Worked example: EGI Check-in

EGI Check-in (a Keycloak instance) is the motivating example; the feature is
generic OIDC and works with any compliant issuer.

```yaml
model_list:
  - model_name: my-model
    litellm_params:
      model: openai/my-model
      api_key: os.environ/UPSTREAM_API_KEY

general_settings:
  oidc_token_exchange:
    issuer: https://aai.egi.eu/auth/realms/egi
    audience: my-litellm-proxy
    # jwks_url defaults to discovery:
    # https://aai.egi.eu/auth/realms/egi/.well-known/openid-configuration
    upsert_user: true
    auto_register_virtual_key: true
```

A service that obtained a token-exchange token for a user calls the proxy
with it as a normal bearer token:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $EXCHANGED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "my-model", "messages": [{"role": "user", "content": "hi"}]}'
```

The first call provisions the user (and, with
`auto_register_virtual_key`, a virtual key attached to that same user, which
the human can retrieve from the Admin UI and use directly). Repeat calls
reuse the existing record and key.
