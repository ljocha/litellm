"""Open-source, license-independent OIDC bearer-token authentication.

Accepts RFC 8693 token-exchange tokens: `sub` identifies the delegated human
user, `act.sub` the calling service (kept in the attached claims only), `aud`
must match this proxy's configured client id. One human maps to exactly one
proxy user record, so budgets and rate limits apply per person regardless of
which service exchanged the token.
"""

import time
from http import HTTPStatus
from typing import Final, TypedDict, assert_never

import jwt as jwt_lib
from jwt import PyJWK, PyJWKSet
from opentelemetry.trace import Span
from pydantic import BaseModel, ConfigDict, TypeAdapter

from litellm._logging import verbose_proxy_logger
from litellm.proxy._types import LitellmUserRoles, OIDCTokenExchangeConfig, UserAPIKeyAuth, hash_token
from litellm.proxy.auth.auth_checks import get_jwt_key_mapping_object, get_user_object
from litellm.proxy.common_utils.user_api_key_cache import UserApiKeyCache
from litellm.proxy.utils import PrismaClient
from litellm.repositories.table_repositories import JWTKeyMappingRepository
from litellm.types.proxy.auth.auth_checks import UserNotFoundError


class _OIDCDiscoveryDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")

    jwks_uri: str | None = None


_jwks_uri_adapter: Final = TypeAdapter(_OIDCDiscoveryDocument)


class _OIDCTokenRejected(Exception):
    def __init__(self, reason: str) -> None:
        self.reason: Final = reason
        super().__init__(reason)


class _OIDCUserUnknown(Exception):
    def __init__(self, user_id: str) -> None:
        self.user_id: Final = user_id
        super().__init__(user_id)


def _discovery_url(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


class OIDCTokenExchangeAuthenticator:
    """Verifies bearer JWTs against a single configured OIDC issuer."""

    _instance: "OIDCTokenExchangeAuthenticator | None" = None

    def __init__(self) -> None:
        self._config: OIDCTokenExchangeConfig | None = None
        self._cached_jwks: tuple[PyJWK, ...] | None = None
        self._cached_jwks_fetched_at: float | None = None
        self._jwks_url: str | None = None

    @classmethod
    def get_instance(cls) -> "OIDCTokenExchangeAuthenticator":
        """Process-wide singleton, configured once at proxy startup"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def update_config(self, config: OIDCTokenExchangeConfig | None) -> None:
        """Swap in a new config, resetting any cached JWKS state."""
        self._config = config
        self._cached_jwks = None
        self._cached_jwks_fetched_at = None
        self._jwks_url = None

    def is_enabled(self) -> bool:
        return self._config is not None

    async def authenticate(
        self,
        *,
        token: str,
        prisma_client: PrismaClient | None,
        user_api_key_cache: UserApiKeyCache,
        parent_otel_span: Span | None = None,
    ) -> UserAPIKeyAuth:
        config: Final = self._config
        if config is None:
            raise RuntimeError("OIDC token exchange auth is not configured")
        claims: Final = await self._verify(token=token, config=config)
        sub: Final = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip():
            raise _OIDCTokenRejected("Token has no subject (`sub`) claim")
        email_claim: Final = claims.get("email")
        email: Final = email_claim if isinstance(email_claim, str) and email_claim.strip() else None

        try:
            user: Final = await get_user_object(
                user_id=sub,
                prisma_client=prisma_client,
                user_api_key_cache=user_api_key_cache,
                user_id_upsert=config.upsert_user,
                parent_otel_span=parent_otel_span,
                user_email=email,
            )
        except UserNotFoundError as e:
            raise _OIDCUserUnknown(sub) from e
        if user is None:
            raise _OIDCUserUnknown(sub)

        if config.auto_register_virtual_key and prisma_client is not None:
            await self._ensure_virtual_key(user_id=sub, prisma_client=prisma_client)

        return UserAPIKeyAuth(
            api_key=None,
            user_id=sub,
            user_email=email or user.user_email,
            user_role=LitellmUserRoles.INTERNAL_USER,
            parent_otel_span=parent_otel_span,
            jwt_claims=claims,
            user_tpm_limit=user.tpm_limit,
            user_rpm_limit=user.rpm_limit,
            user_model_max_budget=user.model_max_budget,
        )

    async def _ensure_virtual_key(self, *, user_id: str, prisma_client: PrismaClient) -> None:
        """Mint a virtual key owned by the OIDC-provisioned user, reusing one minted earlier.

        Idempotency and race safety come from the LiteLLM_JWTKeyMapping unique
        constraint on (jwt_issuer, jwt_claim_name, jwt_claim_value): a repeat
        call finds the existing mapping, and when two first calls race, the
        loser's mapping create hits the unique constraint, deletes its
        orphaned key, and settles on the winner's. No explicit key limits are
        set, so the key inherits the user record's budgets and rate limits.
        """
        config: Final = self._config
        if config is None:
            raise RuntimeError("OIDC token exchange auth is not configured")
        token_hash: str | None = await get_jwt_key_mapping_object(
            jwt_claim_name="sub",
            jwt_claim_value=user_id,
            prisma_client=prisma_client,
            jwt_issuer=config.issuer,
        )
        if token_hash is not None:
            return
        # Inline import required: key_management_endpoints imports
        # user_api_key_auth, which imports this module, so a module-level
        # import here would create a circular dependency.
        from litellm.proxy.management_endpoints.key_management_endpoints import generate_key_helper_fn

        # table_name="key" is required: without it, generate_key_helper_fn
        # falls into the user-upsert branch and tries to insert into
        # LiteLLM_UserTable with user_id=None, failing the NOT NULL @id.
        key_data: Final = await generate_key_helper_fn(
            request_type="key",
            table_name="key",
            llm_router=None,
            user_id=user_id,
            metadata={"auto_registered": True, "oidc_token_exchange": True},
        )
        # generate_key_helper_fn returns the plaintext key in "token"; the
        # persisted row stores its hash, which is what the mapping references.
        minted_hash: Final = hash_token(key_data["token"])
        try:
            await JWTKeyMappingRepository(prisma_client).table.create(
                data={
                    "jwt_issuer": config.issuer,
                    "jwt_claim_name": "sub",
                    "jwt_claim_value": user_id,
                    "token": minted_hash,
                    "created_by": "oidc_token_exchange",
                    "updated_by": "oidc_token_exchange",
                }
            )
        except Exception as e:
            if "unique" not in str(e).lower() and "p2002" not in str(e).lower():
                raise
            # A concurrent request won the race. The key just persisted is
            # orphaned (nothing maps to it, but it is a valid API key), so
            # delete it; the winner's mapping already covers this identity.
            verbose_proxy_logger.debug(
                "OIDC token exchange: mint race lost for sub=%s; deleting orphaned key",
                user_id,
            )
            try:
                await prisma_client.db.litellm_verificationtoken.delete(where={"token": minted_hash})
            except Exception as delete_err:
                verbose_proxy_logger.warning(
                    "OIDC token exchange: failed to delete orphaned key after mint race: %s",
                    delete_err,
                )

    async def _verify(self, *, token: str, config: OIDCTokenExchangeConfig) -> dict:
        try:
            unverified_header: Final = jwt_lib.get_unverified_header(token)
        except jwt_lib.PyJWTError as e:
            raise _OIDCTokenRejected("Bearer token is not a well-formed JWT") from e
        signing_jwk: Final = await self._signing_jwk(kid=unverified_header.get("kid"), config=config)
        # Only `kid` is read from the unverified header; the algorithm comes
        # from the JWKS key entry so an attacker-controlled `alg` (alg:none,
        # HS256-with-public-key confusion) can never be selected.
        algorithm: Final = signing_jwk.algorithm_name or "RS256"
        try:
            return jwt_lib.decode(
                token,
                signing_jwk.key,
                algorithms=[algorithm],
                issuer=config.issuer,
                audience=config.audience,
                options={"verify_aud": not config.disable_audience_validation},
            )
        except jwt_lib.InvalidIssuerError as e:
            raise _OIDCTokenRejected("Token issuer does not match the configured OIDC issuer") from e
        except jwt_lib.InvalidAudienceError as e:
            raise _OIDCTokenRejected("Token audience does not include this proxy") from e
        except jwt_lib.ExpiredSignatureError as e:
            raise _OIDCTokenRejected("Token has expired") from e
        except jwt_lib.ImmatureSignatureError as e:
            raise _OIDCTokenRejected("Token is not yet valid (`nbf` in the future)") from e
        except jwt_lib.InvalidSignatureError as e:
            raise _OIDCTokenRejected("Token signature failed verification") from e
        except jwt_lib.PyJWTError as e:
            raise _OIDCTokenRejected("Bearer token failed OIDC verification") from e

    async def _signing_jwk(self, *, kid: object, config: OIDCTokenExchangeConfig) -> PyJWK:
        jwks_url: Final = await self._resolve_jwks_url(config=config)
        keys: Final = await self._fetch_jwks(jwks_url=jwks_url, config=config)
        for jwk in keys:
            if not kid or jwk.key_id == kid:
                return jwk
        raise _OIDCTokenRejected(f"No JWKS key matching kid={kid!r} at {jwks_url}")

    async def _resolve_jwks_url(self, *, config: OIDCTokenExchangeConfig) -> str:
        if config.jwks_url is not None:
            return config.jwks_url
        cached: Final = self._jwks_url
        if cached is not None:
            return cached
        discovery_url: Final = _discovery_url(config.issuer)
        from litellm.llms.custom_httpx.http_handler import get_async_httpx_client, httpxSpecialProvider

        client: Final = get_async_httpx_client(llm_provider=httpxSpecialProvider.Oauth2Check)
        resp: Final = await client.get(discovery_url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        jwks_uri: Final = _jwks_uri_adapter.validate_python(resp.json()).jwks_uri
        if jwks_uri is None or not jwks_uri.strip():
            raise ValueError(
                f"OIDC discovery document at {discovery_url!r} has no 'jwks_uri'. "
                "Set general_settings.oidc_token_exchange.jwks_url explicitly."
            )
        self._jwks_url = jwks_uri
        return jwks_uri

    async def _fetch_jwks(self, *, jwks_url: str, config: OIDCTokenExchangeConfig) -> tuple[PyJWK, ...]:
        cached_keys: Final = self._cached_jwks
        fetched_at: Final = self._cached_jwks_fetched_at
        now: Final = time.monotonic()
        if cached_keys is not None and fetched_at is not None and now - fetched_at < config.jwks_cache_ttl:
            return cached_keys
        from litellm.llms.custom_httpx.http_handler import get_async_httpx_client, httpxSpecialProvider

        client: Final = get_async_httpx_client(llm_provider=httpxSpecialProvider.Oauth2Check)
        resp: Final = await client.get(jwks_url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        body: Final = resp.json()
        raw_keys: Final = body.get("keys", []) if isinstance(body, dict) else []
        try:
            jwks_set: Final = PyJWKSet.from_dict({"keys": raw_keys})
        except Exception as e:
            raise ValueError(f"Failed to parse JWKS from {jwks_url!r}: {e}") from e
        keys: Final = tuple(jwks_set.keys)
        self._cached_jwks = keys
        self._cached_jwks_fetched_at = now
        return keys


def raise_oidc_token_exchange_error(error: _OIDCTokenRejected | _OIDCUserUnknown) -> None:
    from litellm.proxy._types import ProxyErrorTypes, ProxyException

    match error:
        case _OIDCTokenRejected(reason=reason):
            raise ProxyException(
                message=f"OIDC token exchange authentication failed: {reason}",
                type=ProxyErrorTypes.oidc_token_exchange_auth_error.value,
                param=None,
                code=HTTPStatus.UNAUTHORIZED,
            )
        case _OIDCUserUnknown(user_id=user_id):
            raise ProxyException(
                message=f"OIDC identity '{user_id}' is not a known proxy user and upsert_user is disabled",
                type=ProxyErrorTypes.oidc_token_exchange_auth_error.value,
                param=None,
                code=HTTPStatus.FORBIDDEN,
            )
        case _:
            assert_never(error)
