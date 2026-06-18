import time
import asyncio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock


def _make_async_client_mock(response):
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestIsIamConfigured:
    def test_configured(self):
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="https://iam.example.com",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
        ):
            from dws_autopilot_mcp.token_manager import is_iam_configured
            assert is_iam_configured() is True

    def test_not_configured_missing_endpoint(self):
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
        ):
            from dws_autopilot_mcp.token_manager import is_iam_configured
            assert is_iam_configured() is False

    def test_not_configured_all_empty(self):
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="",
            IAM_USERNAME="",
            IAM_PASSWORD="",
        ):
            from dws_autopilot_mcp.token_manager import is_iam_configured
            assert is_iam_configured() is False


class TestBuildIamAuthBody:
    def test_with_project_id_uses_project_scope(self):
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_USERNAME="user1",
            IAM_PASSWORD="pass1",
            IAM_DOMAIN_NAME="domain1",
            IAM_PROJECT_ID="proj1",
        ):
            from dws_autopilot_mcp.token_manager import _build_iam_auth_body
            body = _build_iam_auth_body()
            assert body["auth"]["identity"]["password"]["user"]["domain"]["name"] == "domain1"
            assert body["auth"]["scope"] == {"project": {"id": "proj1"}}

    def test_without_project_id_uses_domain_scope(self):
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_USERNAME="user1",
            IAM_PASSWORD="pass1",
            IAM_DOMAIN_NAME="domain1",
            IAM_PROJECT_ID="",
        ):
            from dws_autopilot_mcp.token_manager import _build_iam_auth_body
            body = _build_iam_auth_body()
            assert body["auth"]["scope"] == {"domain": {"name": "domain1"}}

    def test_without_domain_name_fallback_to_username(self):
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_USERNAME="user1",
            IAM_PASSWORD="pass1",
            IAM_DOMAIN_NAME="",
            IAM_PROJECT_ID="",
        ):
            from dws_autopilot_mcp.token_manager import _build_iam_auth_body
            body = _build_iam_auth_body()
            assert body["auth"]["identity"]["password"]["user"]["domain"]["name"] == "user1"
            assert body["auth"]["scope"] == {"domain": {"name": "user1"}}


class TestParseTokenResponse:
    def _make_response(self, status_code=201, token="test-token", expires_at=""):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = status_code
        resp.text = "error body"
        resp.headers = {"X-Subject-Token": token} if token else {}
        token_data = {}
        if expires_at:
            token_data = {"token": {"expires_at": expires_at}}
        resp.json.return_value = token_data
        return resp

    def test_success_with_expires_at(self):
        from dws_autopilot_mcp.token_manager import _parse_token_response
        resp = self._make_response(token="tok123", expires_at="2026-01-01T00:00:00Z")
        token, expire_ts = _parse_token_response(resp)
        assert token == "tok123"
        assert expire_ts > 0

    def test_success_without_expires_at(self):
        from dws_autopilot_mcp.token_manager import _parse_token_response
        resp = self._make_response(token="tok123", expires_at="")
        token, expire_ts = _parse_token_response(resp)
        assert token == "tok123"
        assert expire_ts > time.time()

    def test_non_201_raises(self):
        from dws_autopilot_mcp.token_manager import _parse_token_response
        import pytest
        resp = self._make_response(status_code=401, token="")
        with pytest.raises(RuntimeError, match="IAM auth failed"):
            _parse_token_response(resp)

    def test_missing_token_header_raises(self):
        from dws_autopilot_mcp.token_manager import _parse_token_response
        import pytest
        resp = self._make_response(token="", expires_at="")
        resp.headers = {}
        with pytest.raises(RuntimeError, match="missing X-Subject-Token"):
            _parse_token_response(resp)


class TestFetchTokenFromIam:
    def test_success(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 201
        mock_resp.headers = {"X-Subject-Token": "iam-token-123"}
        mock_resp.json.return_value = {"token": {"expires_at": "2099-01-01T00:00:00Z"}}
        mock_client = _make_async_client_mock(mock_resp)

        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="https://iam.example.com",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
            IAM_DOMAIN_NAME="",
            IAM_PROJECT_ID="proj1",
        ), patch("dws_autopilot_mcp.token_manager.httpx.AsyncClient", return_value=mock_client):
            from dws_autopilot_mcp.token_manager import _fetch_token_from_iam
            token, expire_ts = asyncio.run(_fetch_token_from_iam())
            assert token == "iam-token-123"
            assert expire_ts > 0


class TestGetToken:
    def test_returns_cached_token(self):
        import dws_autopilot_mcp.token_manager as tm
        tm._cached_token = "cached-tok"
        tm._token_expire_at = time.time() + 3600
        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="https://iam.example.com",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
        ):
            from dws_autopilot_mcp.token_manager import get_token
            result = asyncio.run(get_token())
            assert result == "cached-tok"

    def test_fetches_new_token_when_expired(self):
        import dws_autopilot_mcp.token_manager as tm
        tm._cached_token = ""
        tm._token_expire_at = 0.0

        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="https://iam.example.com",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
            IAM_DOMAIN_NAME="",
            IAM_PROJECT_ID="proj1",
        ), patch(
            "dws_autopilot_mcp.token_manager._fetch_token_from_iam",
            new=AsyncMock(return_value=("fresh-tok", time.time() + 3600)),
        ):
            from dws_autopilot_mcp.token_manager import get_token
            result = asyncio.run(get_token())
            assert result == "fresh-tok"

    def test_fetches_new_token_when_near_expiry(self):
        import dws_autopilot_mcp.token_manager as tm
        tm._cached_token = "almost-expired"
        tm._token_expire_at = time.time() + 100

        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="https://iam.example.com",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
            IAM_DOMAIN_NAME="",
            IAM_PROJECT_ID="proj1",
        ), patch(
            "dws_autopilot_mcp.token_manager._fetch_token_from_iam",
            new=AsyncMock(return_value=("refreshed-tok", time.time() + 7200)),
        ):
            from dws_autopilot_mcp.token_manager import get_token
            result = asyncio.run(get_token())
            assert result == "refreshed-tok"


class TestForceRefresh:
    def test_force_refresh_clears_cache_and_fetches(self):
        import dws_autopilot_mcp.token_manager as tm
        tm._cached_token = "old-tok"
        tm._token_expire_at = time.time() + 3600

        with patch.multiple(
            "dws_autopilot_mcp.token_manager",
            IAM_ENDPOINT="https://iam.example.com",
            IAM_USERNAME="user",
            IAM_PASSWORD="pass",
            IAM_DOMAIN_NAME="",
            IAM_PROJECT_ID="proj1",
        ), patch(
            "dws_autopilot_mcp.token_manager._fetch_token_from_iam",
            new=AsyncMock(return_value=("refreshed-tok", time.time() + 7200)),
        ):
            from dws_autopilot_mcp.token_manager import force_refresh
            result = asyncio.run(force_refresh())
            assert result == "refreshed-tok"
            assert tm._cached_token == "refreshed-tok"
