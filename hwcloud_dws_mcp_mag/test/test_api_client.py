import asyncio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock


def _make_async_client_mock(response):
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.request = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestBuildHeaders:
    def test_default_headers_with_token(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            _DEFAULT_HEADERS={"X-Custom": "val"},
            DWS_MCP_TOKEN="static-tok",
        ):
            from dws_autopilot_mcp.api_client import _build_headers
            headers = _build_headers()
            assert headers["X-Custom"] == "val"
            assert "X-Auth-Token" not in headers

    def test_custom_headers_merge(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            _DEFAULT_HEADERS={},
            DWS_MCP_TOKEN="",
        ):
            from dws_autopilot_mcp.api_client import _build_headers
            headers = _build_headers(headers={"X-Extra": "extra"})
            assert headers["X-Extra"] == "extra"

    def test_no_token_no_header(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            _DEFAULT_HEADERS={},
            DWS_MCP_TOKEN="",
        ):
            from dws_autopilot_mcp.api_client import _build_headers
            headers = _build_headers()
            assert "X-Auth-Token" not in headers


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


class TestHandle401Retry:
    def test_iam_not_configured_returns_none(self):
        with patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False):
            from dws_autopilot_mcp.api_client import _handle_401_retry
            result = asyncio.run(_handle_401_retry("GET", "/test", {}, {}))
            assert result is None

    def test_refresh_failure_returns_error(self):
        with patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.api_client.force_refresh", new=AsyncMock(side_effect=Exception("refresh fail"))):
            from dws_autopilot_mcp.api_client import _handle_401_retry
            result = asyncio.run(_handle_401_retry("GET", "/test", {}, {}))
            assert result["code"] == -1
            assert "refresh failed" in result["msg"]

    def test_retry_still_401_returns_error(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401

        mock_client = _make_async_client_mock(mock_resp)

        with patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.api_client.force_refresh", new=AsyncMock(return_value="new-tok")), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client):
            from dws_autopilot_mcp.api_client import _handle_401_retry
            result = asyncio.run(_handle_401_retry("GET", "/test", {}, {}))
            assert result["code"] == -1
            assert "did not resolve" in result["msg"]

    def test_retry_success_returns_response(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200

        mock_client = _make_async_client_mock(mock_resp)

        with patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.api_client.force_refresh", new=AsyncMock(return_value="new-tok")), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client):
            from dws_autopilot_mcp.api_client import _handle_401_retry
            result = asyncio.run(_handle_401_retry("GET", "/test", {}, {}))
            assert isinstance(result, httpx.Response)


class TestRequest:
    def test_success_request(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="static-tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client), \
             patch("dws_autopilot_mcp.api_client._handle_error_response", new=AsyncMock(return_value=None)):
            from dws_autopilot_mcp.api_client import _request
            result = asyncio.run(_request("GET", "/test"))
            assert result == {"data": "ok"}

    def test_request_with_iam_token(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.api_client.get_token", new=AsyncMock(return_value="iam-tok")), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client), \
             patch("dws_autopilot_mcp.api_client._handle_error_response", new=AsyncMock(return_value=None)):
            from dws_autopilot_mcp.api_client import _request
            result = asyncio.run(_request("GET", "/test"))
            assert result == {"data": "ok"}

    def test_request_401_retry_returns_dict_error(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.api_client.get_token", new=AsyncMock(return_value="iam-tok")), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client), \
             patch("dws_autopilot_mcp.api_client._handle_401_retry", new=AsyncMock(return_value={"code": -1, "msg": "retry failed", "data": None})):
            from dws_autopilot_mcp.api_client import _request
            result = asyncio.run(_request("GET", "/test"))
            assert result["code"] == -1

    def test_request_error_response(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 500

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="static-tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client), \
             patch("dws_autopilot_mcp.api_client._handle_error_response", new=AsyncMock(return_value={"error": "server error", "status_code": 500})):
            from dws_autopilot_mcp.api_client import _request
            result = asyncio.run(_request("GET", "/test"))
            assert result["status_code"] == 500

    def test_request_401_no_iam_returns_error(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401

        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="static-tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client), \
             patch("dws_autopilot_mcp.api_client._handle_error_response", new=AsyncMock(return_value={"code": -1, "msg": "401 Unauthorized", "data": None})):
            from dws_autopilot_mcp.api_client import _request
            result = asyncio.run(_request("GET", "/test"))
            assert result["code"] == -1

    def test_request_401_iam_retry_with_response(self):
        mock_resp_401 = MagicMock(spec=httpx.Response)
        mock_resp_401.status_code = 401
        mock_resp_401.json.return_value = {"data": "retry_ok"}

        mock_resp_retry = MagicMock(spec=httpx.Response)
        mock_resp_retry.status_code = 200
        mock_resp_retry.json.return_value = {"data": "retry_ok"}

        mock_client = _make_async_client_mock(mock_resp_401)

        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.api_client.get_token", new=AsyncMock(return_value="iam-tok")), \
             patch("dws_autopilot_mcp.api_client._make_client", return_value=mock_client), \
             patch("dws_autopilot_mcp.api_client._handle_401_retry", new=AsyncMock(return_value=mock_resp_retry)), \
             patch("dws_autopilot_mcp.api_client._handle_error_response", new=AsyncMock(return_value=None)):
            from dws_autopilot_mcp.api_client import _request
            result = asyncio.run(_request("GET", "/test"))
            assert result == {"data": "retry_ok"}


class TestGetHostOverview:
    def test_basic_call(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "hosts"})):
            from dws_autopilot_mcp.api_client import get_host_overview
            result = asyncio.run(get_host_overview(project_id="p1", cluster_id="c1"))
            assert result == {"data": "hosts"}

    def test_with_optional_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "hosts"})) as mock_req:
            from dws_autopilot_mcp.api_client import get_host_overview
            result = asyncio.run(get_host_overview(
                project_id="p1", cluster_id="c1",
                filter="host_name", value="node1",
                sub_filter="disk", sub_value="sda",
                offset=0, limit=10, rate_type="avg",
            ))
            assert result == {"data": "hosts"}


class TestGetMetricData:
    def test_basic_call(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "metrics"})):
            from dws_autopilot_mcp.api_client import get_metric_data
            result = asyncio.run(get_metric_data(
                project_id="p1", cluster_id="c1",
                metric_name="cpu_usage", from_ts=1000, to_ts=2000,
                order_by="cpu_usage", sort_by="ASC",
            ))
            assert result == {"data": "metrics"}

    def test_without_optional_params(self):
        with patch.multiple(
            "dws_autopilot_mcp.api_client",
            DMS_MONITORING_BASE_URL="https://dms.example.com",
            DWS_MCP_TOKEN="tok",
        ), patch("dws_autopilot_mcp.api_client.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.api_client._request", new=AsyncMock(return_value={"data": "metrics"})) as mock_req:
            from dws_autopilot_mcp.api_client import get_metric_data
            result = asyncio.run(get_metric_data(
                project_id="p1", cluster_id="c1",
                metric_name="cpu_usage", from_ts=1000, to_ts=2000,
            ))
            assert result == {"data": "metrics"}
