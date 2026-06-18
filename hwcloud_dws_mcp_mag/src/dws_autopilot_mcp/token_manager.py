
import time
import logging
import httpx
import ssl
from datetime import datetime

logger = logging.getLogger("dws_autopilot_mcp")

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE
_ssl_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

from .config import IAM_ENDPOINT, IAM_USERNAME, IAM_PASSWORD, IAM_DOMAIN_NAME, IAM_PROJECT_ID

_cached_token: str = ""
_token_expire_at: float = 0.0
_EXPIRY_MARGIN_SECONDS = 300


def is_iam_configured() -> bool:
    return bool(IAM_ENDPOINT and IAM_USERNAME and IAM_PASSWORD)


def _build_iam_auth_body() -> dict:
    domain_name = IAM_DOMAIN_NAME or IAM_USERNAME
    scope = {"project": {"id": IAM_PROJECT_ID}} if IAM_PROJECT_ID else {"domain": {"name": domain_name}}
    return {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": IAM_USERNAME,
                        "password": IAM_PASSWORD,
                        "domain": {"name": domain_name},
                    }
                },
            },
            "scope": scope,
        }
    }


def _parse_token_response(resp: httpx.Response) -> tuple[str, float]:
    if resp.status_code != 201:
        raise RuntimeError(f"IAM auth failed: {resp.status_code} {resp.text}")
    token = resp.headers.get("X-Subject-Token", "")
    if not token:
        raise RuntimeError("IAM response missing X-Subject-Token header")
    token_data = resp.json()
    expires_at = token_data.get("token", {}).get("expires_at", "")
    if expires_at:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        expire_ts = dt.timestamp()
    else:
        expire_ts = time.time() + 86400
    return token, expire_ts


async def _fetch_token_from_iam() -> tuple[str, float]:
    body = _build_iam_auth_body()
    async with httpx.AsyncClient(
        timeout=30.0, verify=_ssl_ctx, trust_env=False
    ) as client:
        resp = await client.post(
            f"{IAM_ENDPOINT}/v3/auth/tokens",
            json=body,
        )
    return _parse_token_response(resp)


async def get_token() -> str:
    global _cached_token, _token_expire_at
    if _cached_token and time.time() < _token_expire_at - _EXPIRY_MARGIN_SECONDS:
        return _cached_token
    token, expire_ts = await _fetch_token_from_iam()
    _cached_token = token
    _token_expire_at = expire_ts
    logger.info("Token refreshed, expires at %.0f", expire_ts)
    return _cached_token


async def force_refresh() -> str:
    global _cached_token, _token_expire_at
    _cached_token = ""
    _token_expire_at = 0.0
    return await get_token()
