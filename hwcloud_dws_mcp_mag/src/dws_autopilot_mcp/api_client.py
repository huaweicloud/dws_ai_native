import ssl
import logging
import httpx
from urllib.parse import urlencode

from .apig_sdk import signer

from .config import DMS_MONITORING_BASE_URL, SDK_AK, SDK_SK, PROJECT_ID, HTTP_PROXY, HTTPS_PROXY

_TIMEOUT = 30.0

logger = logging.getLogger("dws_autopilot_mcp")

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE
_ssl_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")



def _error_resp(code: int, msg: str) -> dict:
    return {"code": code, "msg": msg, "data": None}


def _sign_request(method: str, path: str, params: dict | None = None, body: str = "") -> signer.HttpRequest:
    query_str = ""
    if params:
        sorted_params = sorted(params.items())
        query_str = "?" + "&".join(f"{k}={v}" for k, v in sorted_params)

    full_url = f"{DMS_MONITORING_BASE_URL}{path}{query_str}"

    r = signer.HttpRequest(method, full_url)
    r.body = body

    r.headers["Content-Type"] = "application/json"
    r.headers["X-Language"] = "en-us"
    if PROJECT_ID:
        r.headers["X-Project-Id"] = PROJECT_ID

    sig = signer.Signer()
    sig.Key = SDK_AK
    sig.Secret = SDK_SK
    sig.Sign(r)

    return r


def _make_client() -> httpx.AsyncClient:
    proxy = HTTPS_PROXY or HTTP_PROXY or None
    return httpx.AsyncClient(
        timeout=_TIMEOUT,
        verify=_ssl_ctx,
        trust_env=False,
        proxy=proxy,
    )


async def _handle_error_response(resp, method, path) -> dict | None:
    if resp.status_code == 401:
        return _error_resp(
            -1,
            "401 Unauthorized: AK/SK signature verification failed. Please check ak and sk in conf/dws_config.yaml.",
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
    params = kwargs.pop("params", None)
    body = kwargs.pop("data", "")

    r = _sign_request(method, path, params=params, body=body)

    url = f"{r.scheme}://{r.host}{r.uri}"
    if r.query:
        sorted_q = sorted(r.query.items())
        qs = "&".join(f"{k}={v[0]}" if isinstance(v, list) else f"{k}={v}" for k, v in sorted_q)
        url = f"{url}?{qs}"

    async with _make_client() as client:
        resp = await client.request(r.method, url, headers=r.headers, **kwargs)

        err = await _handle_error_response(resp, method, path)
        if err is not None:
            return err
        return resp.json()


async def get_clusters() -> dict:
    path = f"/v2/{PROJECT_ID}/clusters"
    return await _request("GET", path)


async def get_host_overview(
    cluster_id: str,
    offset: int = 0,
    limit: int = 512,
    filter: str | None = None,
    value: str | None = None,
    sub_filter: str | None = None,
    sub_value: str | None = None,
    page_size: int | None = None,
    page_num: int | None = None,
    sub_page_size: int | None = None,
    sub_page_num: int | None = None,
    sort_by: str | None = None,
    order_by: str | None = None,
    sub_sort_by: str | None = None,
    sub_order_by: str | None = None,
    rate_type: str | None = None,
) -> dict:
    path = f"/v1.0/{PROJECT_ID}/dms/host-overview"
    params: dict = {
        "cluster_id": cluster_id,
        "offset": offset,
        "limit": limit,
    }
    if filter is not None:
        params["filter"] = filter
    if value is not None:
        params["value"] = value
    if sub_filter is not None:
        params["sub_filter"] = sub_filter
    if sub_value is not None:
        params["sub_value"] = sub_value
    if page_size is not None:
        params["page_size"] = page_size
    if page_num is not None:
        params["page_num"] = page_num
    if sub_page_size is not None:
        params["sub_page_size"] = sub_page_size
    if sub_page_num is not None:
        params["sub_page_num"] = sub_page_num
    if sort_by is not None:
        params["sort_by"] = sort_by
    if order_by is not None:
        params["order_by"] = order_by
    if sub_sort_by is not None:
        params["sub_sort_by"] = sub_sort_by
    if sub_order_by is not None:
        params["sub_order_by"] = sub_order_by
    if rate_type is not None:
        params["rate_type"] = rate_type
    return await _request("GET", path, params=params)


async def get_metric_data(
    cluster_id: str,
    metric_name: str,
    from_ts: int,
    to_ts: int,
    offset: int = 0,
    limit: int = 50,
    order_by: str | None = None,
    sort_by: str | None = None,
) -> dict:
    path = f"/v1/{PROJECT_ID}/clusters/{cluster_id}/dms/metrics/{metric_name}"
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
