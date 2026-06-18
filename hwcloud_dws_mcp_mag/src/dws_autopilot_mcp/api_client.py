import ssl
import logging
import httpx
from .config import DMS_MONITORING_BASE_URL, DWS_MCP_TOKEN
from .token_manager import is_iam_configured, get_token, force_refresh

_TIMEOUT = 30.0

logger = logging.getLogger("dws_autopilot_mcp")

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE
_ssl_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

_DEFAULT_HEADERS: dict[str, str] = {}


def _build_headers(**kwargs) -> dict:
    headers = {**_DEFAULT_HEADERS, **kwargs.pop("headers", {})}
    return headers


def _error_resp(code: int, msg: str) -> dict:
    return {"code": code, "msg": msg, "data": None}


def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=DMS_MONITORING_BASE_URL,
        timeout=_TIMEOUT,
        verify=_ssl_ctx,
        trust_env=False,
    )


async def _handle_401_retry(method, path, headers, kwargs) -> httpx.Response | dict | None:
    if not is_iam_configured():
        return None
    logger.warning("401 detected, attempting token refresh...")
    try:
        headers["X-Auth-Token"] = await force_refresh()
    except Exception as e:
        logger.error("Token refresh failed: %s", e)
        return _error_resp(-1, f"401 Unauthorized and token refresh failed: {e}")
    async with _make_client() as client:
        resp = await client.request(method, path, headers=headers, **kwargs)
        if resp.status_code == 401:
            return _error_resp(-1, "401 Unauthorized: Token refresh did not resolve the issue.")
        return resp


async def _handle_error_response(resp, method, path) -> dict | None:
    if resp.status_code == 401:
        return _error_resp(
            -1,
            "401 Unauthorized: Token missing or expired. Please check DWS_MCP_TOKEN or IAM credentials in MCP client env settings.",
        )
    if resp.status_code >= 400:
        body = resp.text
        logger.error(f"API error {resp.status_code} on {method} {path}: {body}")
        try:
            error_data: dict = resp.json()
        except Exception:
            error_data: dict = {"error": body}
        error_data["status_code"] = resp.status_code
        return error_data
    return None


async def _request(method: str, path: str, **kwargs) -> dict:
    headers = _build_headers(**kwargs)
    if is_iam_configured():
        headers["X-Auth-Token"] = await get_token()
    elif DWS_MCP_TOKEN:
        headers["X-Auth-Token"] = DWS_MCP_TOKEN

    async with _make_client() as client:
        resp = await client.request(method, path, headers=headers, **kwargs)

        if resp.status_code == 401 and is_iam_configured():
            retry = await _handle_401_retry(method, path, headers, kwargs)
            if retry is not None:
                if isinstance(retry, dict):
                    return retry
                resp = retry

        err = await _handle_error_response(resp, method, path)
        if err is not None:
            return err
        return resp.json()


async def get_host_overview(
    project_id: str,
    cluster_id: str,
    filter: str | None = None,
    value: str | None = None,
    sub_filter: str | None = None,
    sub_value: str | None = None,
    page_size: int = 10,
    page_num: int = 1,
    sub_page_size: int = 10,
    sub_page_num: int = 1,
    sort_by: str = "DESC",
    order_by: str = "",
    sub_sort_by: str = "DESC",
    sub_order_by: str = "",
    offset: int | None = None,
    limit: int | None = None,
    rate_type: str | None = None,
) -> dict:
    path = f"/v1/{project_id}/clusters/{cluster_id}/dms/host-monitor/overview"
    params: dict = {
        "page_size": page_size,
        "page_num": page_num,
        "sub_page_size": sub_page_size,
        "sub_page_num": sub_page_num,
        "sort_by": sort_by,
        "order_by": order_by,
        "sub_sort_by": sub_sort_by,
        "sub_order_by": sub_order_by,
    }
    if filter is not None:
        params["filter"] = filter
    if value is not None:
        params["value"] = value
    if sub_filter is not None:
        params["sub_filter"] = sub_filter
    if sub_value is not None:
        params["sub_value"] = sub_value
    if offset is not None:
        params["offset"] = offset
    if limit is not None:
        params["limit"] = limit
    if rate_type is not None:
        params["rate_type"] = rate_type
    return await _request("GET", path, params=params)


async def get_metric_data(
    project_id: str,
    cluster_id: str,
    metric_name: str,
    from_ts: int,
    to_ts: int,
    offset: int = 0,
    limit: int = 50,
    order_by: str | None = None,
    sort_by: str | None = None,
) -> dict:
    path = f"/v1/{project_id}/clusters/{cluster_id}/dms/metrics/{metric_name}"
    params: dict = {
        "from": from_ts,
        "to": to_ts,
        "offset": offset,
        "limit": limit,
    }
    if order_by is not None:
        params["order_by"] = order_by
    if sort_by is not None:
        params["sort_by"] = sort_by
    return await _request("GET", path, params=params)
