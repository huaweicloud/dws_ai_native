import asyncio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock


def _make_async_client_mock(response):
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.request = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestErrorResp:
    def test_error_resp_structure(self):
        from dws_autopilot_mcp.api_client import _error_resp
        result = _error_resp(-1, "test error")
        assert result == {"code": -1, "msg": "test error", "data": None}


class TestHandleErrorResponse:
    def _make_response(self, status_code, text="", json_data=None):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = status_code
        resp.text = text
        if json_data is not None:
            resp.json.return_value = json_data
        else:
            resp.json.side_effect = Exception("not json")
        return resp

    def test_401_returns_error(self):
        from dws_autopilot_mcp.api_client import _handle_error_response
        resp = self._make_response(401)
        result = asyncio.run(_handle_error_response(resp, "GET", "/test"))
        assert result is not None
        assert result["code"] == -1
        assert "401" in result["msg"]

    def test_500_with_json_body(self):
        from dws_autopilot_mcp.api_client import _handle_error_response
        resp = self._make_response(500, text="err", json_data={"error_code": "DWS.500"})
        result = asyncio.run(_handle_error_response(resp, "GET", "/test"))
        assert result is not None
        assert result["status_code"] == 500
        assert result["error_code"] == "DWS.500"

    def test_500_with_non_json_body(self):
        from dws_autopilot_mcp.api_client import _handle_error_response
        resp = self._make_response(500, text="plain error")
        result = asyncio.run(_handle_error_response(resp, "GET", "/test"))
        assert result is not None
        assert result["error"] == "plain error"
        assert result["status_code"] == 500

    def test_200_returns_none(self):
        from dws_autopilot_mcp.api_client import _handle_error_response
        resp = self._make_response(200)
        result = asyncio.run(_handle_error_response(resp, "GET", "/test"))
        assert result is None


class TestMakeClient:
    def test_make_client_with_https_proxy(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            HTTPS_PROXY="https://proxy.example.com:8080",
            HTTP_PROXY="http://proxy.example.com:8080",
        ):
            from dws_autopilot_mcp.api_client import _make_client
            client = _make_client()
            assert client is not None

    def test_make_client_with_http_proxy_only(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            HTTPS_PROXY="",
            HTTP_PROXY="http://proxy.example.com:8080",
        ):
            from dws_autopilot_mcp.api_client import _make_client
            client = _make_client()
            assert client is not None

    def test_make_client_no_proxy(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            HTTPS_PROXY="",
            HTTP_PROXY="",
        ):
            from dws_autopilot_mcp.api_client import _make_client
            client = _make_client()
            assert client is not None


class TestGetClusters:
    def test_basic_call(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ), patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"clusters": []})):
            from dws_autopilot_mcp.api_client import get_clusters
            result = asyncio.run(get_clusters())
            assert result == {"clusters": []}


class TestGetHostOverview:
    def test_basic_call(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ), patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "hosts"})):
            from dws_autopilot_mcp.api_client import get_host_overview
            result = asyncio.run(get_host_overview(cluster_id="c1"))
            assert result == {"data": "hosts"}

    def test_with_optional_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ), patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "hosts"})) as mock_req:
            from dws_autopilot_mcp.api_client import get_host_overview
            result = asyncio.run(get_host_overview(
                cluster_id="c1",
                filter="host_name", value="node1",
                sub_filter="disk", sub_value="sda",
                offset=0, limit=10, rate_type="avg",
            ))
            assert result == {"data": "hosts"}

    def test_with_all_optional_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ), patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "hosts"})) as mock_req:
            from dws_autopilot_mcp.api_client import get_host_overview
            result = asyncio.run(get_host_overview(
                cluster_id="c1",
                filter="host_name", value="node1",
                sub_filter="disk", sub_value="sda",
                page_size=20, page_num=2,
                sub_page_size=5, sub_page_num=3,
                sort_by="ASC", order_by="cpu_usage",
                sub_sort_by="DESC", sub_order_by="disk_usage_avg",
                rate_type="avg",
            ))
            assert result == {"data": "hosts"}
            call_kwargs = mock_req.call_args
            params = call_kwargs[1].get("params", {}) if "params" in call_kwargs[1] else call_kwargs[0][1] if len(call_kwargs[0]) > 1 else {}
            assert params["page_size"] == 20
            assert params["page_num"] == 2
            assert params["sub_page_size"] == 5
            assert params["sub_page_num"] == 3
            assert params["sort_by"] == "ASC"
            assert params["order_by"] == "cpu_usage"
            assert params["sub_sort_by"] == "DESC"
            assert params["sub_order_by"] == "disk_usage_avg"
            assert params["rate_type"] == "avg"


class TestGetMetricData:
    def test_basic_call(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ), patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "metrics"})):
            from dws_autopilot_mcp.api_client import get_metric_data
            result = asyncio.run(get_metric_data(
                cluster_id="c1",
                metric_name="cpu_usage", from_ts=1000, to_ts=2000,
                order_by="cpu_usage", sort_by="ASC",
            ))
            assert result == {"data": "metrics"}

    def test_without_optional_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ), patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "metrics"})):
            from dws_autopilot_mcp.api_client import get_metric_data
            result = asyncio.run(get_metric_data(
                cluster_id="c1",
                metric_name="cpu_usage", from_ts=1000, to_ts=2000,
            ))
            assert result == {"data": "metrics"}


class TestSignRequest:
    def test_sign_request_with_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dws.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ):
            from dws_autopilot_mcp.api_client import _sign_request
            r = _sign_request("GET", "/v1/test", params={"cluster_id": "c1", "offset": "0"})
            assert r.uri == "/v1/test"
            assert "cluster_id" in r.query
            assert "Authorization" in r.headers
            assert r.headers["X-Project-Id"] == "test_proj"

    def test_sign_request_without_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dws.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
        ):
            from dws_autopilot_mcp.api_client import _sign_request
            r = _sign_request("GET", "/v1/test")
            assert r.query == {}
            assert "Authorization" in r.headers

    def test_sign_request_without_project_id(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dws.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="",
        ):
            from dws_autopilot_mcp.api_client import _sign_request
            r = _sign_request("GET", "/v1/test")
            assert "X-Project-Id" not in r.headers


class TestRequestQueryString:
    def test_request_url_includes_query_params(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dws.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
            HTTPS_PROXY="",
            HTTP_PROXY="",
        ), patch("dws_autopilot_mcp.api_client.httpx.AsyncClient", return_value=mock_client):
            from dws_autopilot_mcp.api_client import _request
            asyncio.run(_request("GET", "/v1/test", params={"cluster_id": "c1", "limit": "10"}))
            call_args = mock_client.request.call_args
            url = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("url", "")
            assert "cluster_id=c1" in url
            assert "limit=10" in url

    def test_request_url_without_query_params(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dws.example.com",
            SDK_AK="test_ak",
            SDK_SK="test_sk",
            PROJECT_ID="test_proj",
            HTTPS_PROXY="",
            HTTP_PROXY="",
        ), patch("dws_autopilot_mcp.api_client.httpx.AsyncClient", return_value=mock_client):
            from dws_autopilot_mcp.api_client import _request
            asyncio.run(_request("GET", "/v1/test"))
            call_args = mock_client.request.call_args
            url = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("url", "")
            assert "?" not in url
