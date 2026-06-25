import json
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock


class TestListTools:
    def test_list_tools_returns_three_tools(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        names = [t.name for t in tools]
        assert len(tools) == 3
        assert "dws_autopilot_get_clusters" in names
        assert "dws_autopilot_get_hosts" in names
        assert "dws_autopilot_get_metric" in names

    def test_host_overview_tool_required_fields(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        host_tool = next(t for t in tools if t.name == "dws_autopilot_get_hosts")
        assert "cluster_id" in host_tool.inputSchema["required"]

    def test_metric_tool_required_fields(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        metric_tool = next(t for t in tools if t.name == "dws_autopilot_get_metric")
        for field in ["cluster_id", "metric_name", "from_ts", "to_ts"]:
            assert field in metric_tool.inputSchema["required"]


class TestCallTool:
    def test_call_get_clusters(self):
        with patch("dws_autopilot_mcp.server.get_clusters", new=AsyncMock(return_value={"clusters": []})):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_autopilot_get_clusters",
                {},
            ))
            assert len(result) == 1
            parsed = json.loads(result[0].text)
            assert parsed == {"clusters": []}

    def test_call_host_overview(self):
        with patch("dws_autopilot_mcp.server.get_host_overview", new=AsyncMock(return_value={"hosts": []})):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_autopilot_get_hosts",
                {"cluster_id": "c1"},
            ))
            assert len(result) == 1
            parsed = json.loads(result[0].text)
            assert parsed == {"hosts": []}

    def test_call_metric_data(self):
        with patch("dws_autopilot_mcp.server.get_metric_data", new=AsyncMock(return_value={"metrics": []})):
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_autopilot_get_metric",
                {
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
                "dws_autopilot_get_hosts",
                {"cluster_id": "c1"},
            ))
            parsed = json.loads(result[0].text)
            assert "error" in parsed
            assert "API error" in parsed["error"]

    def test_call_host_overview_with_optional_params(self):
        with patch("dws_autopilot_mcp.server.get_host_overview", new=AsyncMock(return_value={"hosts": []})) as mock:
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_autopilot_get_hosts",
                {
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

    def test_call_metric_cpu_io_diagnose_detail_with_query_fields(self):
        mock_response = {
            "code": 0,
            "msg": "OK",
            "data": [
                {
                    "cpu_rate": 44.85,
                    "query_id": "145241087996680670",
                    "query": "SELECT count(*) FROM t1",
                    "datname": "hulei_test",
                    "inst_name": "dn_6005",
                    "username": "dbadmin",
                    "io_read": 0.0,
                    "io_write": 0.0,
                    "count": 1,
                    "ctime": 1782049642000,
                    "host_id": 183490,
                    "virtual_cluster_id": 97434,
                },
                {
                    "cpu_rate": 2.31,
                    "datname": "postgres",
                    "inst_name": "cn_5001",
                    "username": "Ruby",
                    "io_read": 0.0,
                    "io_write": 2.66,
                    "count": 7,
                    "ctime": 1782049402000,
                    "host_id": 183492,
                    "virtual_cluster_id": 97434,
                },
            ],
        }
        with patch("dws_autopilot_mcp.server.get_metric_data", new=AsyncMock(return_value=mock_response)) as mock:
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_autopilot_get_metric",
                {
                    "cluster_id": "c1",
                    "metric_name": "cpu_io_diagnose_detail",
                    "from_ts": 1782049367311,
                    "to_ts": 1782049967311,
                },
            ))
            assert len(result) == 1
            parsed = json.loads(result[0].text)
            assert parsed["code"] == 0
            data = parsed["data"]
            assert len(data) == 2
            # First record has query_id and query
            assert data[0]["query_id"] == "145241087996680670"
            assert data[0]["query"] == "SELECT count(*) FROM t1"
            # Second record may not have query_id/query (aggregated record)
            assert "query_id" not in data[1]
            assert "query" not in data[1]

    def test_metric_tool_description_mentions_cpu_io_diagnose_detail(self):
        from dws_autopilot_mcp.server import list_tools
        tools = asyncio.run(list_tools())
        metric_tool = next(t for t in tools if t.name == "dws_autopilot_get_metric")
        desc = metric_tool.inputSchema["properties"]["metric_name"]["description"]
        assert "cpu_io_diagnose_detail" in desc
        assert "query_id" in desc
        assert "query" in desc

    def test_call_metric_data_with_optional_params(self):
        with patch("dws_autopilot_mcp.server.get_metric_data", new=AsyncMock(return_value={"metrics": []})) as mock:
            from dws_autopilot_mcp.server import call_tool
            result = asyncio.run(call_tool(
                "dws_autopilot_get_metric",
                {
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
    def test_main_with_ak_sk(self):
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio = MagicMock()
        mock_stdio.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio.__aexit__ = AsyncMock(return_value=False)

        with patch("dws_autopilot_mcp.config.HTTP_PROXY", ""), \
             patch("dws_autopilot_mcp.config.HTTPS_PROXY", ""), \
             patch("dws_autopilot_mcp.config.SDK_AK", "test_ak"), \
             patch("dws_autopilot_mcp.config.SDK_SK", "test_sk"), \
             patch("dws_autopilot_mcp.server.stdio_server", return_value=mock_stdio), \
             patch("dws_autopilot_mcp.server.server") as mock_server_obj:
            mock_server_obj.run = AsyncMock()
            mock_server_obj.create_initialization_options = MagicMock(return_value={})
            from dws_autopilot_mcp.server import main
            asyncio.run(main())

    def test_main_with_proxy_logs(self):
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio = MagicMock()
        mock_stdio.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio.__aexit__ = AsyncMock(return_value=False)

        with patch("dws_autopilot_mcp.config.HTTP_PROXY", "http://proxy:8080"), \
             patch("dws_autopilot_mcp.config.HTTPS_PROXY", ""), \
             patch("dws_autopilot_mcp.config.SDK_AK", "test_ak"), \
             patch("dws_autopilot_mcp.config.SDK_SK", "test_sk"), \
             patch("dws_autopilot_mcp.server.stdio_server", return_value=mock_stdio), \
             patch("dws_autopilot_mcp.server.server") as mock_server_obj:
            mock_server_obj.run = AsyncMock()
            mock_server_obj.create_initialization_options = MagicMock(return_value={})
            from dws_autopilot_mcp.server import main
            asyncio.run(main())

    def test_main_no_ak_sk_warning(self):
        mock_read = AsyncMock()
        mock_write = AsyncMock()
        mock_stdio = MagicMock()
        mock_stdio.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
        mock_stdio.__aexit__ = AsyncMock(return_value=False)

        with patch("dws_autopilot_mcp.config.HTTP_PROXY", ""), \
             patch("dws_autopilot_mcp.config.HTTPS_PROXY", ""), \
             patch("dws_autopilot_mcp.config.SDK_AK", ""), \
             patch("dws_autopilot_mcp.config.SDK_SK", ""), \
             patch("dws_autopilot_mcp.server.stdio_server", return_value=mock_stdio), \
             patch("dws_autopilot_mcp.server.server") as mock_server_obj:
            mock_server_obj.run = AsyncMock()
            mock_server_obj.create_initialization_options = MagicMock(return_value={})
            from dws_autopilot_mcp.server import main
            asyncio.run(main())
