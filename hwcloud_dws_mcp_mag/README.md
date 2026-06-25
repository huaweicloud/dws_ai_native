English | [中文](README_zh.md)

# DWS Autopilot MCP Server

## Table of Contents
- [1. Introduction](#1-introduction)
- [2. Features](#2-features)
  - [2.1 Tools](#21-tools)
  - [2.2 Authentication](#22-authentication)
  - [2.3 Config Encryption](#23-config-encryption)
- [3. Installation & Configuration](#3-installation--configuration)
  - [3.1 Prerequisites](#31-prerequisites)
  - [3.2 Installation](#32-installation)
  - [3.3 Configuration](#33-configuration)
  - [3.4 Config Management CLI](#34-config-management-cli)
  - [3.5 Client Configuration](#35-client-configuration)
- [4. Getting Started](#4-getting-started)

## 1. Introduction
MCP (Model Context Protocol) is an open protocol standard proposed by Anthropic in November 2024, aiming to solve the fragmentation problem of interaction between large language models and external systems (such as databases, APIs). By standardizing the interface, it allows LLMs to dynamically understand tool functions and perform tasks, reducing integration costs.
Setting up the DWS Autopilot MCP Server allows users to leverage LLM capabilities to query DWS cluster monitoring metrics and host information through natural language, enabling intelligent operations.

## 2. Features

### 2.1 Tools
DWS Autopilot MCP Server provides the following tools:

1. **dws_autopilot_get_clusters**
   Query DWS cluster list. No parameters required.

2. **dws_autopilot_get_hosts**
   Query DWS cluster host information with filtering, pagination, and sorting support.
   - Required: `cluster_id` (string) — Cluster ID
   - Optional filtering: `filter` (host_name / work_ip), `value`, `sub_filter`, `sub_value`
   - Optional pagination: `page_size` (default 10, max 2000), `page_num` (default 1), `offset` (default 0), `limit` (default 512)
   - Optional sorting: `order_by` (cpu_usage, mem_usage, disk_usage_avg, disk_io, tcp_resend_rate, net_io), `sort_by` (ASC / DESC, default DESC)

3. **dws_autopilot_get_metric**
   Query DWS cluster metric time-series data.
   - Required: `cluster_id` (string), `metric_name` (string), `from_ts` (13-digit unix timestamp in ms), `to_ts` (13-digit unix timestamp in ms)
   - Supported metrics: `cpu_usage`, `mem_usage`, `disk_usage_avg`, `tcp_resend_rate`, `disk_io`, `net_io`, `cpu_io_diagnose_detail` (returns per-query detail including query_id and query fields)
   - Optional: `offset` (default 0), `limit` (max 1000, default 50), `order_by`, `sort_by` (ASC / DESC)

### 2.2 Authentication
AK/SK signature authentication is used:

- **AK/SK Signature Mode**: Use Huawei Cloud Access Key (AK) and Secret Key (SK) to sign each API request. The signature automatically adds `Authorization` and `X-Sdk-Date` headers for authentication.
- If `project_id` is configured, the `X-Project-Id` header is automatically added for multi-project scenarios.

### 2.3 Config Encryption
Sensitive fields (AK, SK) support AES-256-GCM encrypted storage:
- Auto-detects plaintext and encrypts on MCP Server startup
- Machine fingerprint-based key protection, bound to the current machine environment
- Master key dual protection: crypter (stored in yaml) + cryptComponent (stored in crypt.json)

## 3. Installation & Configuration

### 3.1 Prerequisites
+ Python 3.10 or above
+ pip package manager

### 3.2 Installation
```bash
# Clone the repository
git clone <repo_url>
cd dws_autopilot_mcp

# Install dependencies
pip install .
```

### 3.3 Configuration
The configuration file is located at `conf/dws_config.yaml`. Fill in the configuration before first use:

```yaml
region_id: "cn-north-7"
ak: "your_access_key"
sk: "your_secret_key"
project_id: "your_project_id"
http_proxy: "http://proxy.example.com:8080"
https_proxy: "http://proxy.example.com:8080"
proxy_username: "your_proxy_user"
proxy_password: "your_proxy_password"
```

**Parameter Reference:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `region_id` | Huawei Cloud region ID, used to auto-generate API endpoints | `cn-north-7` |
| `ak` | Huawei Cloud Access Key (enter plaintext, auto-encrypted on startup) | - |
| `sk` | Huawei Cloud Secret Key (enter plaintext, auto-encrypted on startup) | - |
| `project_id` | Project ID, used for `X-Project-Id` header in multi-project scenarios | - |
| `http_proxy` | HTTP proxy URL (can include credentials, or use `proxy_username`/`proxy_password` separately) | `http://proxy.example.com:8080` |
| `https_proxy` | HTTPS proxy URL | `http://proxy.example.com:8080` |
| `proxy_username` | Proxy authentication username (auto-injected into proxy URL with percent-encoding) | - |
| `proxy_password` | Proxy authentication password (auto percent-encoded and injected into proxy URL) | - |

> `region_id` automatically generates `DMS_MONITORING_BASE_URL` (`https://dws.{region_id}.myhuaweicloud.com`), no manual configuration needed.

> You can also specify the config file path via the `DWS_MCP_CONFIG` environment variable.

### 3.4 Config Management CLI
After installation, the `dws-mcp-config` CLI tool is available. Run commands from the project root directory (`dws_autopilot_mcp/`):

#### init - Initialize or Update Configuration
The `init` command sets configuration parameters:

```bash
python -m dws_autopilot_mcp.config_cli init --region_id cn-north-7 --ak your_ak --sk your_sk --project_id your_project_id
```

> The `init` command supports partial updates — only specified parameters are updated, unspecified ones remain unchanged. For example, to update only the AK: `python -m dws_autopilot_mcp.config_cli init --ak new_ak`.
>
> After updating configuration, restart the MCP Server to auto-encrypt sensitive fields (AK, SK).

#### Other Commands

```bash
# Manually trigger encryption (auto-executed on MCP Server startup as well)
python -m dws_autopilot_mcp.config_cli encrypt

# Show config status (secrets are masked as ******)
python -m dws_autopilot_mcp.config_cli show

# Reset config to empty template (clear all parameters and remove crypt.json)
python -m dws_autopilot_mcp.config_cli reset
```

> The `encrypt`, `show`, and `reset` commands require no additional parameters.

### 3.5 Client Configuration
Using OpenClaw as an example, add the following to MCP Servers configuration:

```json
{
  "dws_autopilot_mcp": {
    "type": "local",
    "command": [
      "/path/to/python.exe",
      "-m",
      "dws_autopilot_mcp.server"
    ],
    "environment": {
      "PYTHONPATH": "/path/to/dws_autopilot_mcp/src"
    }
  }
}
```

> Replace `/path/to/python.exe` with your local Python executable path, and `/path/to/dws_autopilot_mcp/src` with the absolute path to this project's `src` directory. On Windows, use `;` as the PYTHONPATH separator; on Linux/macOS, use `:`.

## 4. Getting Started
After completing the configuration, you can interact with your DWS cluster using natural language, for example:
- "Query XXXX cluster host information"
- "Show XXXX cluster CPU usage for the last hour"
