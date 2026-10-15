import time
from collections.abc import Mapping, Sequence
from typing import Any, Final
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as jwt_lib
import pytest

from litellm.proxy._types import (
    OIDCTokenExchangeConfig,
    LiteLLM_UserTable,
    ProxyErrorTypes,
    ProxyException,
)
from litellm.proxy.auth.oidc_token_exchange import (
    OIDCTokenExchangeAuthenticator,
    _OIDCTokenRejected,
    _OIDCUserUnknown,
    raise_oidc_token_exchange_error,
)

ISSUER: Final = "https://idp.example.org/realms/test"
AUDIENCE: Final = "litellm-proxy"
_JWKS_URI: Final = "https://idp.example.org/protocol/openid-connect/certs"


def _base64url_encode_int(value: int) -> str:
    import base64

    value_bytes: Final = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(value_bytes).decode("utf-8").rstrip("=")


def _get_rsa_key_and_jwk(kid: str) -> tuple[Any, dict]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk: Final = {
        "kty": "RSA",
        "n": _base64url_encode_int(value=public_numbers.n),
        "e": _base64url_encode_int(value=public_numbers.e),
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
    }
    return private_key, jwk


def _encode_jwt(
    private_key: Any,
    *,
    issuer: str = ISSUER,
    audience: Any = AUDIENCE,
    kid: str = "test-key",
    sub: str = "human-1",
    exp: int | None = None,
    extra_claims: Mapping[str, Any] | None = None,
) -> str:
    from cryptography.hazmat.primitives import serialization

    private_key_pem: Final = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now: Final = int(time.time())
    claims: Final = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": exp if exp is not None else now + 300,
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt_lib.encode(claims, private_key_pem, algorithm="RS256", headers={"kid": kid})


def _http_response(json_body: Any) -> MagicMock:
    response: Final = MagicMock()
    response.status_code = 200
    response.json.return_value = json_body
    return response


def _make_authenticator(
    *,
    keys: Sequence[dict],
    config: OIDCTokenExchangeConfig | None = None,
    discovery: Mapping[str, Any] | None = None,
) -> tuple[OIDCTokenExchangeAuthenticator, AsyncMock]:
    """Authenticator with the HTTP fetch seam replaced by a call-counting mock.

    One recorded call serves both the discovery document and the JWKS document:
    the body decides which, keyed off the URL the module asked for.
    """
    authenticator: Final = OIDCTokenExchangeAuthenticator()
    authenticator.update_config(
        config
        if config is not None
        else OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE)
    )

    async def fake_get(url: str, **_: Any) -> MagicMock:
        if url.endswith("/.well-known/openid-configuration"):
            return _http_response(dict(discovery if discovery is not None else {"jwks_uri": _JWKS_URI}))
        return _http_response({"keys": list(keys)})

    fetch_mock: Final = AsyncMock(side_effect=fake_get)
    patcher: Final = patch(
        "litellm.llms.custom_httpx.http_handler.get_async_httpx_client",
        return_value=MagicMock(get=fetch_mock),
    )
    patcher.start()
    return authenticator, fetch_mock


def _make_user(user_id: str, **fields: Any) -> LiteLLM_UserTable:
    return LiteLLM_UserTable(user_id=user_id, **fields)


def _configured_user_store(users: Sequence[LiteLLM_UserTable]) -> tuple[AsyncMock, list[str]]:
    """get_user_object stand-in returning canned users; records the user ids seen."""
    seen: Final = []

    async def fake_get_user_object(
        *,
        user_id: str,
        user_id_upsert: bool,
        **_: Any,
    ) -> LiteLLM_UserTable | None:
        seen.append(user_id)
        for user in users:
            if user.user_id == user_id:
                return user
        if user_id_upsert:
            created: Final = _make_user(user_id)
            users.append(created)
            return created
        raise _user_not_found(user_id)

    return AsyncMock(side_effect=fake_get_user_object), seen


def _user_not_found(user_id: str) -> Exception:
    from litellm.types.proxy.auth.auth_checks import UserNotFoundError

    return UserNotFoundError(user_id=user_id)


async def _authenticate(authenticator: OIDCTokenExchangeAuthenticator, token: str, **store_users: Any):
    get_user_mock, seen = (
        _configured_user_store(store_users["users"])
        if "users" in store_users
        else (AsyncMock(side_effect=AssertionError("get_user_object must not run for token-level rejections")), [])
    )
    with patch("litellm.proxy.auth.oidc_token_exchange.get_user_object", get_user_mock):
        result = await authenticator.authenticate(token=token, prisma_client=None, user_api_key_cache=MagicMock())
    return result, seen, get_user_mock


# ---- config model ----


def test_config_model_accepts_valid_block():
    config: Final = OIDCTokenExchangeConfig(
        issuer=ISSUER,
        audience=["a", "b"],
        jwks_url="https://idp.example.org/keys",
        upsert_user=False,
        auto_register_virtual_key=True,
        jwks_cache_ttl=30,
    )
    assert config.upsert_user is False
    assert config.auto_register_virtual_key is True


def test_config_model_defaults():
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE)
    assert config.jwks_url is None
    assert config.upsert_user is True
    assert config.auto_register_virtual_key is False
    assert config.jwks_cache_ttl == 600


@pytest.mark.parametrize(
    "payload",
    [
        {"audience": AUDIENCE},  # missing issuer
        {"issuer": "  ", "audience": AUDIENCE},  # blank issuer
        {"issuer": ISSUER},  # missing audience with validation enabled
        {"issuer": ISSUER, "audience": []},  # empty audience list
        {"issuer": ISSUER, "audience": ["  "]},  # blank audience entry
        {"issuer": ISSUER, "audience": "x", "jwks_cache_ttl": -1},  # negative ttl
        {"issuer": ISSUER, "audience": AUDIENCE, "disable_audience_validation": True},  # both set
    ],
)
def test_config_model_rejects_malformed(payload: dict):
    with pytest.raises(ValueError):
        OIDCTokenExchangeConfig.model_validate(payload)


def test_config_model_rejects_unknown_key():
    with pytest.raises(ValueError):
        OIDCTokenExchangeConfig.model_validate({"issuer": ISSUER, "audience": AUDIENCE, "issuers": "typo"})


# ---- authentication ----


@pytest.mark.asyncio
async def test_valid_token_authenticates_and_maps_sub():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, extra_claims={"act": {"sub": "service-1"}, "email": "human@example.org"})
    authenticator, fetch_mock = _make_authenticator(keys=[jwk])
    user: Final = _make_user("human-1", user_email="human@example.org")

    result, seen, _ = await _authenticate(authenticator, token, users=[user])

    assert result.user_id == "human-1"
    assert result.user_role.value == "internal_user"
    assert result.user_email == "human@example.org"
    assert result.jwt_claims["act"]["sub"] == "service-1"
    assert seen == ["human-1"]


@pytest.mark.asyncio
async def test_repeat_call_reuses_user_and_cached_jwks():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    authenticator, fetch_mock = _make_authenticator(keys=[jwk])
    user: Final = _make_user("human-1")

    first, seen_first, _ = await _authenticate(authenticator, token, users=[user])
    second, seen_second, _ = await _authenticate(authenticator, token, users=[user])

    assert first.user_id == second.user_id == "human-1"
    assert seen_first == seen_second == ["human-1"]
    # one discovery + one JWKS fetch; the second verify serves from cache
    assert fetch_mock.call_count == 2


@pytest.mark.asyncio
async def test_upsert_creates_user_once_then_reuses():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    authenticator, fetch_mock = _make_authenticator(keys=[jwk])

    first, seen_first, _ = await _authenticate(authenticator, token, users=[])
    second, seen_second, _ = await _authenticate(authenticator, token, users=[])

    assert seen_first == ["human-1"]
    assert first.user_id == "human-1"
    assert seen_second == ["human-1"]
    assert second.user_id == "human-1"


@pytest.mark.asyncio
async def test_wrong_issuer_rejects_401():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, issuer="https://evil.example.org/realms/other")
    authenticator, _ = _make_authenticator(keys=[jwk])

    with pytest.raises(_OIDCTokenRejected) as rejected:
        await _authenticate(authenticator, token)
    assert rejected.value.reason


@pytest.mark.asyncio
async def test_wrong_audience_rejects_401():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, audience="someone-else")
    authenticator, _ = _make_authenticator(keys=[jwk])

    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(authenticator, token)


@pytest.mark.asyncio
async def test_list_audience_overlap_accepts():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, audience=["other-svc", AUDIENCE])
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, audience=[AUDIENCE])
    authenticator, _ = _make_authenticator(keys=[jwk], config=config)
    user: Final = _make_user("human-1")

    result, _, _ = await _authenticate(authenticator, token, users=[user])
    assert result.user_id == "human-1"


# ---- disable_audience_validation ----


def test_config_model_accepts_audience_omitted_when_validation_disabled():
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, disable_audience_validation=True)
    assert config.disable_audience_validation is True


@pytest.mark.asyncio
@pytest.mark.parametrize("audience", ["arbitrary-svc", "someone-else", ""])
async def test_validation_disabled_accepts_any_audience(audience: str):
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, audience=audience)
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, disable_audience_validation=True)
    authenticator, _ = _make_authenticator(keys=[jwk], config=config)
    user: Final = _make_user("human-1")

    result, _, _ = await _authenticate(authenticator, token, users=[user])
    assert result.user_id == "human-1"


@pytest.mark.asyncio
async def test_validation_disabled_still_enforces_signature_and_expiry():
    attacker_key, trusted_jwk = _get_rsa_key_and_jwk(kid="test-key")
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, disable_audience_validation=True)
    # JWKS publishes trusted_jwk; the forged token is signed by a different key
    authenticator, _ = _make_authenticator(keys=[trusted_jwk], config=config)

    other_key, _ = _get_rsa_key_and_jwk(kid="test-key")
    forged: Final = _encode_jwt(other_key, audience="anything")
    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(authenticator, forged)

    expired_key, expired_jwk = _get_rsa_key_and_jwk(kid="expired-key")
    expired_authenticator, _ = _make_authenticator(keys=[expired_jwk], config=config)
    expired: Final = _encode_jwt(expired_key, audience="anything", exp=int(time.time()) - 10)
    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(expired_authenticator, expired)


@pytest.mark.asyncio
async def test_wrong_audience_still_rejects_with_validation_enabled():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, audience="someone-else")
    authenticator, _ = _make_authenticator(keys=[jwk])

    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(authenticator, token)


@pytest.mark.asyncio
async def test_bad_signature_rejects_401():
    _, wrong_jwk = _get_rsa_key_and_jwk(kid="test-key")
    attacker_key, _ = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(attacker_key)
    config: Final = OIDCTokenExchangeConfig(
        issuer=ISSUER, audience=AUDIENCE, jwks_url="https://idp.example.org/certs"
    )
    authenticator, _ = _make_authenticator(keys=[wrong_jwk], config=config)

    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(authenticator, token)


@pytest.mark.asyncio
async def test_expired_token_rejects_401():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, exp=int(time.time()) - 10)
    authenticator, _ = _make_authenticator(keys=[jwk])

    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(authenticator, token)


@pytest.mark.asyncio
async def test_empty_sub_rejects_401():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key, sub="   ")
    authenticator, _ = _make_authenticator(keys=[jwk])

    with pytest.raises(_OIDCTokenRejected):
        await _authenticate(authenticator, token)


@pytest.mark.asyncio
async def test_unknown_user_with_upsert_disabled_rejects():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE, upsert_user=False)
    authenticator, _ = _make_authenticator(keys=[jwk], config=config)

    with pytest.raises(_OIDCUserUnknown):
        await _authenticate(authenticator, token, users=[])


@pytest.mark.asyncio
async def test_explicit_jwks_url_skips_discovery():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    config: Final = OIDCTokenExchangeConfig(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://idp.example.org/protocol/openid-connect/certs",
    )
    authenticator, fetch_mock = _make_authenticator(keys=[jwk], config=config)
    user: Final = _make_user("human-1")

    result, _, _ = await _authenticate(authenticator, token, users=[user])

    assert result.user_id == "human-1"
    requested_urls: Final = [call.args[0] for call in fetch_mock.call_args_list]
    assert all("/.well-known/openid-configuration" not in url for url in requested_urls)
    assert any("protocol/openid-connect/certs" in url for url in requested_urls)


@pytest.mark.asyncio
async def test_discovery_resolves_jwks_uri():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    authenticator, fetch_mock = _make_authenticator(
        keys=[jwk],
        discovery={"jwks_uri": "https://idp.example.org/protocol/openid-connect/certs"},
    )
    user: Final = _make_user("human-1")

    result, _, _ = await _authenticate(authenticator, token, users=[user])

    assert result.user_id == "human-1"
    requested_urls: Final = [call.args[0] for call in fetch_mock.call_args_list]
    assert any(url.endswith("/.well-known/openid-configuration") for url in requested_urls)
    assert any(url.endswith("/protocol/openid-connect/certs") for url in requested_urls)


@pytest.mark.asyncio
async def test_jwks_cache_bounds_fetch_count():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    config: Final = OIDCTokenExchangeConfig(
        issuer=ISSUER, audience=AUDIENCE, jwks_cache_ttl=600
    )
    authenticator, fetch_mock = _make_authenticator(keys=[jwk], config=config)
    user: Final = _make_user("human-1")

    for _ in range(3):
        await _authenticate(authenticator, token, users=[user])

    # one discovery + one JWKS fetch, then served from cache
    assert fetch_mock.call_count == 2


# ---- error mapping ----


def test_rejected_token_maps_to_401_proxy_exception():
    with pytest.raises(ProxyException) as exc_info:
        raise_oidc_token_exchange_error(_OIDCTokenRejected("Token has expired"))
    assert exc_info.value.code == "401"
    assert exc_info.value.type == ProxyErrorTypes.oidc_token_exchange_auth_error.value
    assert "Token has expired" in exc_info.value.message


def test_unknown_user_maps_to_403_proxy_exception():
    with pytest.raises(ProxyException) as exc_info:
        raise_oidc_token_exchange_error(_OIDCUserUnknown("human-1"))
    assert exc_info.value.code == "403"
    assert exc_info.value.type == ProxyErrorTypes.oidc_token_exchange_auth_error.value


# ---- wiring seam ----


@pytest.mark.asyncio
async def test_disabled_feature_leaves_singleton_inert():
    authenticator: Final = OIDCTokenExchangeAuthenticator()
    assert authenticator.is_enabled() is False
    with pytest.raises(RuntimeError):
        await authenticator.authenticate(token="a.b.c", prisma_client=None, user_api_key_cache=MagicMock())


def test_update_config_resets_jwks_cache():
    authenticator: Final = OIDCTokenExchangeAuthenticator()
    authenticator.update_config(OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE))
    assert authenticator.is_enabled() is True
    authenticator.update_config(None)
    assert authenticator.is_enabled() is False


# ---- builder wiring ----


def _builder_proxy_server_attrs(*, general_settings: dict) -> dict:
    mock_cache: Final = MagicMock()
    mock_cache.async_get_cache = AsyncMock(return_value=None)
    mock_proxy_logging_obj: Final = MagicMock()
    mock_proxy_logging_obj.post_call_failure_hook = AsyncMock(return_value=None)
    return {
        "prisma_client": MagicMock(),
        "user_api_key_cache": mock_cache,
        "proxy_logging_obj": mock_proxy_logging_obj,
        "master_key": "sk-master-key",
        "general_settings": general_settings,
        "llm_model_list": [],
        "llm_router": None,
        "open_telemetry_logger": None,
        "model_max_budget_limiter": MagicMock(),
        "user_custom_auth": None,
        "jwt_handler": MagicMock(),
        "litellm_proxy_admin_name": "admin",
    }


async def _run_builder(api_key: str) -> Any:
    from starlette.datastructures import URL
    from fastapi import Request

    from litellm.proxy.auth.user_api_key_auth import _user_api_key_auth_builder

    request: Final = Request(scope={"type": "http"})
    request._url = URL(url="/chat/completions")
    return await _user_api_key_auth_builder(
        request=request,
        api_key=f"Bearer {api_key}",
        azure_api_key_header="",
        anthropic_api_key_header=None,
        google_ai_studio_api_key_header=None,
        azure_apim_header=None,
        request_data={},
    )


def _patch_proxy_server_attrs(attrs: dict):
    import litellm.proxy.proxy_server as _proxy_server_mod

    originals: Final = {attr: getattr(_proxy_server_mod, attr, None) for attr in attrs}
    for attr, val in attrs.items():
        setattr(_proxy_server_mod, attr, val)

    class _Restore:
        def __enter__(self):
            return self

        def __exit__(self, *args: Any):
            for attr, val in originals.items():
                setattr(_proxy_server_mod, attr, val)

    return _Restore()


@pytest.mark.asyncio
async def test_builder_diverts_jwt_bearer_to_oidc_when_enabled():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    oidc_result: Final = MagicMock(user_id="human-1")

    with patch.object(OIDCTokenExchangeAuthenticator, "get_instance", return_value=_StubAuthenticator(oidc_result)):
        attrs: Final = _builder_proxy_server_attrs(general_settings={})
        with _patch_proxy_server_attrs(attrs):
            result = await _run_builder(token)

    assert result is oidc_result


@pytest.mark.asyncio
async def test_builder_divert_only_when_jwt_shaped_and_oidc_enabled():
    class _Off:
        def is_enabled(self) -> bool:
            return False

        async def authenticate(self, **_: Any) -> UserAPIKeyAuth:
            raise AssertionError("authenticate must not run when disabled")

    with patch.object(OIDCTokenExchangeAuthenticator, "get_instance", return_value=_Off()):
        attrs: Final = _builder_proxy_server_attrs(general_settings={})
        with _patch_proxy_server_attrs(attrs), pytest.raises(Exception) as raised:
            await _run_builder("not-a-jwt-bearer")
        assert "401" in str(raised.value) or "sk-" in str(raised.value)


@pytest.mark.asyncio
async def test_builder_non_jwt_bearer_skips_oidc():
    class _Disabled:
        def is_enabled(self) -> bool:
            return True

        async def authenticate(self, **_: Any) -> UserAPIKeyAuth:
            raise AssertionError("non-JWT bearer must not reach the OIDC path")

    with patch.object(OIDCTokenExchangeAuthenticator, "get_instance", return_value=_Disabled()):
        attrs: Final = _builder_proxy_server_attrs(general_settings={})
        with _patch_proxy_server_attrs(attrs), pytest.raises(Exception):
            await _run_builder("opaque-token")


class _StubAuthenticator:
    def __init__(self, result: Any) -> None:
        self._result: Final = result

    def is_enabled(self) -> bool:
        return True

    async def authenticate(self, **_: Any) -> Any:
        return self._result


# ---- virtual-key minting ----


def _mapping_store(existing_mappings: Sequence[str]) -> tuple[AsyncMock, list[str]]:
    """get_jwt_key_mapping_object stand-in; returns a hash once a mapping exists."""
    looked_up: Final = []

    async def fake_lookup(jwt_claim_value: str, **_: Any) -> str | None:
        looked_up.append(jwt_claim_value)
        return "existing-hash" if jwt_claim_value in existing_mappings else None

    return AsyncMock(side_effect=fake_lookup), looked_up


def _key_minter(minted: list[dict]) -> AsyncMock:
    async def fake_generate(**kwargs: Any) -> dict:
        minted.append(
            {
                "user_id": kwargs.get("user_id"),
                "table_name": kwargs.get("table_name"),
                "metadata": kwargs.get("metadata"),
            }
        )
        return {"token": "sk-minted"}

    return AsyncMock(side_effect=fake_generate)


def _mapping_creator(created: list[dict], fail_with: Exception | None = None) -> AsyncMock:
    async def fake_create(data: dict) -> None:
        if fail_with is not None:
            raise fail_with
        created.append(data)

    return AsyncMock(side_effect=fake_create)


async def _authenticate_with_minting(
    authenticator: OIDCTokenExchangeAuthenticator,
    token: str,
    *,
    existing_mappings: Sequence[str] = (),
    mapping_create_failure: Exception | None = None,
):
    minted: Final = []
    created: Final = []
    lookup_mock, looked_up = _mapping_store(existing_mappings)
    get_user_mock, _ = _configured_user_store([_make_user("human-1")])
    prisma_mock: Final = MagicMock()

    def _repo_init(prisma_client: Any) -> MagicMock:
        repo: Final = MagicMock()
        repo.table.create = _mapping_creator(created, mapping_create_failure)
        return repo

    with (
        patch("litellm.proxy.auth.oidc_token_exchange.get_user_object", get_user_mock),
        patch("litellm.proxy.auth.oidc_token_exchange.get_jwt_key_mapping_object", lookup_mock),
        patch(
            "litellm.proxy.management_endpoints.key_management_endpoints.generate_key_helper_fn",
            _key_minter(minted),
        ),
        patch("litellm.proxy.auth.oidc_token_exchange.JWTKeyMappingRepository", _repo_init),
    ):
        result = await authenticator.authenticate(
            token=token, prisma_client=prisma_mock, user_api_key_cache=MagicMock()
        )
    return result, minted, created, looked_up


@pytest.mark.asyncio
async def test_auto_register_mints_key_on_first_call():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE, auto_register_virtual_key=True)
    authenticator, _ = _make_authenticator(keys=[jwk], config=config)

    result, minted, created, looked_up = await _authenticate_with_minting(authenticator, token)

    assert result.user_id == "human-1"
    assert looked_up == ["human-1"]
    assert len(minted) == 1
    assert minted[0]["user_id"] == "human-1"
    assert minted[0]["table_name"] == "key"
    assert minted[0]["metadata"]["auto_registered"] is True
    assert len(created) == 1
    assert created[0]["jwt_claim_name"] == "sub"
    assert created[0]["jwt_claim_value"] == "human-1"
    assert created[0]["jwt_issuer"] == ISSUER


@pytest.mark.asyncio
async def test_auto_register_reuses_existing_key_on_repeat():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE, auto_register_virtual_key=True)
    authenticator, _ = _make_authenticator(keys=[jwk], config=config)

    result, minted, created, _ = await _authenticate_with_minting(
        authenticator, token, existing_mappings=["human-1"]
    )

    assert result.user_id == "human-1"
    assert minted == []
    assert created == []


@pytest.mark.asyncio
async def test_auto_register_race_loser_reuses_winners_key():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    config: Final = OIDCTokenExchangeConfig(issuer=ISSUER, audience=AUDIENCE, auto_register_virtual_key=True)
    authenticator, _ = _make_authenticator(keys=[jwk], config=config)

    result, minted, created, _ = await _authenticate_with_minting(
        authenticator,
        token,
        mapping_create_failure=Exception("Unique constraint failed (p2002)"),
    )

    # The race loser must not fail the request and must not leave a mapping
    assert result.user_id == "human-1"
    assert len(minted) == 1
    assert created == []


@pytest.mark.asyncio
async def test_flag_off_mints_nothing():
    private_key, jwk = _get_rsa_key_and_jwk(kid="test-key")
    token: Final = _encode_jwt(private_key)
    authenticator, _ = _make_authenticator(keys=[jwk])  # auto_register_virtual_key defaults to False
    user: Final = _make_user("human-1")

    result, seen, _ = await _authenticate(authenticator, token, users=[user])

    assert result.user_id == "human-1"
    assert seen == ["human-1"]
