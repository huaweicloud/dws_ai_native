import json
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock


class TestListTools:
    def test_list_tools_returns_two_tools(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        assert len(tools) == 2
        assert tools[0].name == "dws_service_autopilot_host_overview"
        assert tools[1].name == "get_metric_data_list"

    def test_host_overview_tool_required_fields(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        host_tool = tools[0]
        assert "project_id" in host_tool.inputSchema["required"]
        assert "cluster_id" in host_tool.inputSchema["required"]

    def test_metric_tool_required_fields(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        metric_tool = tools[1]
        for field in ["project_id", "cluster_id", "metric_name", "from_ts", "to_ts"]:
            assert field in metric_tool.inputSchema["required"]


class TestCallTool:
    def test_call_host_overview(self):
        with patch("dws_autopilot_mcp.server.get_host_overview", new=AsyncMock(return_value={"hosts": []})):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_service_autopilot_host_overview",
                {"project_id": "p1", "cluster_id": "c1"},
            ))
            assert len(result) == 1
            parsed = json.loads(result[0].text)
            assert parsed == {"hosts": []}

    def test_call_metric_data(self):
        with patch("dws_autopilot_mcp.server.get_metric_data", new=AsyncMock(return_value={"metrics": []})):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "get_metric_data_list",
                {
                    "project_id": "p1",
                    "cluster_id": "c1",
                    "metric_name": "cpu_usage",
                    "from_ts": 1000,
                    "to_ts": 2000,
                },
            ))
            assert len(result) == 1
            parsed = json.loads(result[0].text)
            assert parsed == {"metrics": []}

    def test_call_unknown_tool_returns_error(self):
        from dws_autopilot_mcp.server import call_tool
        result = asyncio.run(call_tool("unknown_tool", {}))
        assert len(result) == 1
        parsed = json.loads(result[0].text)
        assert "error" in parsed
        assert "Unknown tool" in parsed["error"]

    def test_call_tool_with_none_arguments(self):
        with patch("dws_autopilot_mcp.server.get_host_overview", new=AsyncMock(return_value={"hosts": []})):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool("dws_service_autopilot_host_overview", None))
            assert len(result) == 1

    def test_call_tool_exception_returns_error(self):
        with patch("dws_autopilot_mcp.server.get_host_overview", new=AsyncMock(side_effect=Exception("API error"))):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_service_autopilot_host_overview",
                {"project_id": "p1", "cluster_id": "c1"},
            ))
            parsed = json.loads(result[0].text)
            assert "error" in parsed
            assert "API error" in parsed["error"]

    def test_call_host_overview_with_optional_params(self):
        with patch("dws_autopilot_mcp.server.get_host_overview", new=AsyncMock(return_value={"hosts": []})) as mock:
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_service_autopilot_host_overview",
                {
                    "project_id": "p1",
                    "cluster_id": "c1",
                    "filter": "host_name",
                    "value": "node1",
                    "page_size": 20,
                    "page_num": 2,
                    "sort_by": "ASC",
                    "order_by": "cpu_usage",
                },
            ))
            mock.assert_called_once()
            call_kwargs = mock.call_args[1]
            assert call_kwargs["filter"] == "host_name"
            assert call_kwargs["value"] == "node1"
            assert call_kwargs["page_size"] == 20
            assert call_kwargs["sort_by"] == "ASC"

    def test_call_metric_data_with_optional_params(self):
        with patch("dws_autopilot_mcp.server.get_metric_data", new=AsyncMock(return_value={"metrics": []})) as mock:
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "get_metric_data_list",
                {
                    "project_id": "p1",
                    "cluster_id": "c1",
                    "metric_name": "cpu_usage",
                    "from_ts": 1000,
                    "to_ts": 2000,
                    "offset": 10,
                    "limit": 100,
                    "order_by": "cpu_usage",
                    "sort_by": "ASC",
                },
            ))
            mock.assert_called_once()
            call_kwargs = mock.call_args[1]
            assert call_kwargs["offset"] == 10
            assert call_kwargs["limit"] == 100
            assert call_kwargs["sort_by"] == "ASC"


class TestMain:
    def test_main_with_proxy_logs(self):
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio = MagicMock()
        mock_stdio.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio.__aexit__ = AsyncMock(return_value=False)

        with patch("dws_autopilot_mcp.config.HTTP_PROXY", "http://proxy:8080"), \
             patch("dws_autopilot_mcp.config.HTTPS_PROXY", ""), \
             patch("dws_autopilot_mcp.config.DWS_MCP_TOKEN", "tok"), \
             patch("dws_autopilot_mcp.config.IAM_ENDPOINT", ""), \
             patch("dws_autopilot_mcp.config.IAM_USERNAME", ""), \
             patch("dws_autopilot_mcp.token_manager.is_iam_configured", return_value=False), \
             patch("dws_autopilot_mcp.server.stdio_server", return_value=mock_stdio), \
             patch("dws_autopilot_mcp.server.server") as mock_server_obj:
            mock_server_obj.run = AsyncMock()
            mock_server_obj.create_initialization_options = MagicMock(return_value={})
            from dws_autopilot_mcp.server import main
            asyncio.run(main())

    def test_main_with_iam_mode_logs(self):
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio = MagicMock()
        mock_stdio.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio.__aexit__ = AsyncMock(return_value=False)

        with patch("dws_autopilot_mcp.config.HTTP_PROXY", ""), \
             patch("dws_autopilot_mcp.config.HTTPS_PROXY", ""), \
             patch("dws_autopilot_mcp.config.DWS_MCP_TOKEN", ""), \
             patch("dws_autopilot_mcp.config.IAM_ENDPOINT", "https://iam.example.com"), \
             patch("dws_autopilot_mcp.config.IAM_USERNAME", "user1"), \
             patch("dws_autopilot_mcp.token_manager.is_iam_configured", return_value=True), \
             patch("dws_autopilot_mcp.server.stdio_server", return_value=mock_stdio), \
             patch("dws_autopilot_mcp.server.server") as mock_server_obj:
            mock_server_obj.run = AsyncMock()
            mock_server_obj.create_initialization_options = MagicMock(return_value={})
            from dws_autopilot_mcp.server import main
            asyncio.run(main())
