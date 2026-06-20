import asyncio
import json
import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from .api_client import get_host_overview, get_metric_data

server = Server("dws_autopilot_mcp")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="dws_autopilot_mcp-log.out",
)
logger = logging.getLogger("dws_autopilot_mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    logger.info("Listing available tools")
    return [
        Tool(
            name="dws_service_autopilot_host_overview",
            description="查询dws集群节点信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project ID (required).",
                    },
                    "cluster_id": {
                        "type": "string",
                        "description": "Cluster ID (required).",
                    },
                    "filter": {
                        "type": "string",
                        "description": 'Filter key, one of "host_name" or "work_ip".',
                    },
                    "value": {
                        "type": "string",
                        "description": "Filter value, required when filter is set.",
                    },
                    "sub_filter": {
                        "type": "string",
                        "description": "Sub-filter key.",
                    },
                    "sub_value": {
                        "type": "string",
                        "description": "Sub-filter value.",
                    },
                    "page_size": {
                        "type": "integer",
                        "description": "Page size for host list, default 10, max 2000.",
                    },
                    "page_num": {
                        "type": "integer",
                        "description": "Page number for host list, default 1.",
                    },
                    "sub_page_size": {
                        "type": "integer",
                        "description": "Sub-page size, default 10.",
                    },
                    "sub_page_num": {
                        "type": "integer",
                        "description": "Sub-page number, default 1.",
                    },
                    "sort_by": {
                        "type": "string",
                        "description": 'Sort direction "ASC" or "DESC", default "DESC".',
                    },
                    "order_by": {
                        "type": "string",
                        "description": "Order by field, e.g. cpu_usage, mem_usage, disk_usage_avg, disk_io, tcp_resend_rate, net_io.",
                    },
                    "sub_sort_by": {
                        "type": "string",
                        "description": 'Sub-sort direction, default "DESC".',
                    },
                    "sub_order_by": {
                        "type": "string",
                        "description": "Sub-order by field.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Pagination offset, default 0.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Pagination limit, default 512.",
                    },
                    "rate_type": {
                        "type": "string",
                        "description": "Rate type.",
                    },
                },
                "required": ["project_id", "cluster_id"],
            },
        ),
        Tool(
            name="get_metric_data_list",
            description="查询dws集群指标数据",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project ID (required).",
                    },
                    "cluster_id": {
                        "type": "string",
                        "description": "Cluster ID (required).",
                    },
                    "metric_name": {
                        "type": "string",
                        "description": "Metric name, e.g. cpu_usage, mem_usage, disk_usage_avg, tcp_resend_rate, disk_io, net_io.",
                    },
                    "from_ts": {
                        "type": "integer",
                        "description": "Start timestamp in milliseconds (13-digit unix timestamp, required).",
                    },
                    "to_ts": {
                        "type": "integer",
                        "description": "End timestamp in milliseconds (13-digit unix timestamp, required).",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Pagination offset, default 0.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Pagination limit, max 1000, default 50.",
                    },
                    "order_by": {
                        "type": "string",
                        "description": "Order by field.",
                    },
                    "sort_by": {
                        "type": "string",
                        "description": 'Sort direction "ASC" or "DESC".',
                    },
                },
                "required": ["project_id", "cluster_id", "metric_name", "from_ts", "to_ts"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict | None) -> list[TextContent]:
    logger.info(f"Calling tool: {name} with arguments: {arguments}")

    if arguments is None:
        arguments = {}

    try:
        if name == "dws_service_autopilot_host_overview":
            result = await get_host_overview(
                project_id=arguments["project_id"],
                cluster_id=arguments["cluster_id"],
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", 512),
                filter=arguments.get("filter"),
                value=arguments.get("value"),
                sub_filter=arguments.get("sub_filter"),
                sub_value=arguments.get("sub_value"),
                page_size=arguments.get("page_size"),
                page_num=arguments.get("page_num"),
                sub_page_size=arguments.get("sub_page_size"),
                sub_page_num=arguments.get("sub_page_num"),
                sort_by=arguments.get("sort_by"),
                order_by=arguments.get("order_by"),
                sub_sort_by=arguments.get("sub_sort_by"),
                sub_order_by=arguments.get("sub_order_by"),
                rate_type=arguments.get("rate_type"),
            )
        elif name == "get_metric_data_list":
            result = await get_metric_data(
                project_id=arguments["project_id"],
                cluster_id=arguments["cluster_id"],
                metric_name=arguments["metric_name"],
                from_ts=arguments["from_ts"],
                to_ts=arguments["to_ts"],
                offset=arguments.get("offset", 0),
                limit=arguments.get("limit", 50),
                order_by=arguments.get("order_by"),
                sort_by=arguments.get("sort_by"),
            )
        else:
            raise ValueError(f"Unknown tool: {name}")

        return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]

    except Exception as e:
        logger.error(f"Tool call error: {e}")
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, ensure_ascii=False))]


async def main():
    from .config import DWS_MCP_TOKEN, IAM_ENDPOINT, IAM_USERNAME, HTTP_PROXY, HTTPS_PROXY
    from .token_manager import is_iam_configured
    logger.info("Starting dws_autopilot_mcp...")
    if HTTP_PROXY or HTTPS_PROXY:
        logger.info("Proxy: http_proxy=%s, https_proxy=%s", HTTP_PROXY or "(none)", HTTPS_PROXY or "(none)")
    if is_iam_configured():
        logger.info(
            "IAM dynamic token mode: endpoint=%s, username=%s",
            IAM_ENDPOINT,
            IAM_USERNAME,
        )
    elif DWS_MCP_TOKEN:
        logger.info("DWS_MCP_TOKEN is configured (length: %d)", len(DWS_MCP_TOKEN))
    else:
        logger.warning(
            "Neither IAM credentials nor DWS_MCP_TOKEN is configured. "
            "API requests may fail with 401."
        )
    async with stdio_server() as (read_stream, write_stream):
        try:
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise


def main_sync():
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
