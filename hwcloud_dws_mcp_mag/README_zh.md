[English](README.md) | 中文

# DWS Autopilot MCP Server

## 目录
  - [1. 简介](#1-简介)
  - [2. 功能介绍](#2-功能介绍)
    - [2.1 工具](#21-工具)
    - [2.2 认证方式](#22-认证方式)
    - [2.3 配置加密](#23-配置加密)
  - [3. 安装与配置](#3-安装与配置)
    - [3.1 环境准备](#31-环境准备)
    - [3.2 安装](#32-安装)
    - [3.3 配置说明](#33-配置说明)
    - [3.4 配置管理CLI](#34-配置管理cli)
    - [3.5 客户端配置](#35-客户端配置)
  - [4. 开始体验](#4-开始体验)

## 1. 简介
MCP（Model Context Protocol）是由Anthropic于2024年11月提出的开放协议标准，旨在解决大型语言模型与外部系统（如数据库、API）交互的碎片化问题。通过标准化接口，让LLM动态理解工具功能并执行操作，降低集成成本。
通过搭建 DWS Autopilot MCP Server，用户可以借助大模型的能力，以自然语言直接查询DWS集群的监控指标和节点信息，实现智能运维。

## 2. 功能介绍

### 2.1 工具
DWS Autopilot MCP Server 提供以下工具：

1. **dws_autopilot_get_clusters**
   查询DWS集群列表，无需参数。

2. **dws_autopilot_get_hosts**
   查询DWS集群节点信息，支持过滤、分页、排序。
   - 必填：`cluster_id`（字符串）— 集群ID
   - 可选过滤：`filter`（host_name / work_ip）、`value`、`sub_filter`、`sub_value`
   - 可选分页：`page_size`（默认10，最大2000）、`page_num`（默认1）、`offset`（默认0）、`limit`（默认512）
   - 可选排序：`order_by`（cpu_usage、mem_usage、disk_usage_avg、disk_io、tcp_resend_rate、net_io）、`sort_by`（ASC / DESC，默认DESC）

3. **dws_autopilot_get_metric**
   查询DWS集群指标时序数据。
   - 必填：`cluster_id`（字符串）、`metric_name`（字符串）、`from_ts`（13位Unix时间戳，毫秒）、`to_ts`（13位Unix时间戳，毫秒）
   - 支持的指标：`cpu_usage`、`mem_usage`、`disk_usage_avg`、`tcp_resend_rate`、`disk_io`、`net_io`、`cpu_io_diagnose_detail`（返回包含query_id和query字段的逐查询详情）
   - 可选：`offset`（默认0）、`limit`（最大1000，默认50）、`order_by`、`sort_by`（ASC / DESC）

### 2.2 认证方式
采用 AK/SK 签名认证：

- **AK/SK 签名模式**：使用华为云 Access Key（AK）和 Secret Key（SK）对每个 API 请求进行签名，签名后自动添加 `Authorization` 和 `X-Sdk-Date` 请求头完成认证。
- 如果配置了 `project_id`，会自动添加 `X-Project-Id` 请求头，用于多项目场景。

### 2.3 配置加密
敏感字段（AK、SK）支持 AES-256-GCM 加密存储：
- 启动 MCP Server 时自动检测明文并加密
- 基于机器指纹的密钥保护，绑定当前机器环境
- 主密钥双重保护：crypter（存储在 yaml）+ cryptComponent（存储在 crypt.json）

## 3. 安装与配置

### 3.1 环境准备
+ Python 3.10 及以上
+ pip 包管理器

### 3.2 安装
```bash
# 克隆源码
git clone <repo_url>
cd dws_autopilot_mcp

# 安装依赖
pip install .
```

### 3.3 配置说明
配置文件位于 `conf/dws_config.yaml`，首次使用需填写配置：

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

**参数说明：**

| 参数 | 说明 | 示例 |
|------|------|------|
| `region_id` | 华为云区域ID，用于自动生成 API 端点 | `cn-north-7` |
| `ak` | 华为云 Access Key（明文输入，启动后自动加密） | - |
| `sk` | 华为云 Secret Key（明文输入，启动后自动加密） | - |
| `project_id` | 项目ID，用于多项目场景的 `X-Project-Id` 请求头 | - |
| `http_proxy` | HTTP 代理地址（可直接包含认证信息，也可通过 `proxy_username`/`proxy_password` 单独配置） | `http://proxy.example.com:8080` |
| `https_proxy` | HTTPS 代理地址 | `http://proxy.example.com:8080` |
| `proxy_username` | 代理认证用户名（自动注入代理URL，密码自动 percent-encoding） | - |
| `proxy_password` | 代理认证密码（自动 percent-encoding 并注入代理URL） | - |

> `region_id` 会自动生成 `DMS_MONITORING_BASE_URL`（`https://dws.{region_id}.myhuaweicloud.com`），无需手动配置。

> 也可通过环境变量 `DWS_MCP_CONFIG` 指定配置文件路径。

### 3.4 配置管理CLI
安装后提供 `dws-mcp-config` 命令行工具，需在项目根目录（`dws_autopilot_mcp/`）下执行：

#### init - 初始化/更新配置
`init` 命令用于设置配置参数：

```bash
python -m dws_autopilot_mcp.config_cli init --region_id cn-north-7 --ak your_ak --sk your_sk --project_id your_project_id
```

> `init` 命令支持部分更新，仅更新指定的参数，未指定的参数保持不变。例如只更新 AK：`python -m dws_autopilot_mcp.config_cli init --ak new_ak`。
>
> 更新配置后，重启 MCP Server 即可自动加密敏感字段（AK、SK）。

#### 其他命令

```bash
# 手动触发加密（将明文敏感字段加密，启动MCP Server时也会自动执行）
python -m dws_autopilot_mcp.config_cli encrypt

# 查看配置状态（敏感信息以 ****** 显示，不会泄露）
python -m dws_autopilot_mcp.config_cli show

# 重置配置为空模板（清空所有参数，删除 crypt.json）
python -m dws_autopilot_mcp.config_cli reset
```

> `encrypt`、`show`、`reset` 命令无需额外参数。

### 3.5 客户端配置
以 OpenClaw 为例，在 MCP Servers 配置中添加：

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

> 将 `/path/to/python.exe` 替换为本机 Python 可执行文件路径，`/path/to/dws_autopilot_mcp/src` 替换为本项目 `src` 目录的绝对路径。Windows 下 PYTHONPATH 使用 `;` 分隔，Linux/macOS 使用 `:` 分隔。

## 4. 开始体验
完成配置后，即可在客户端中通过自然语言与 DWS 集群交互，例如：
- "查询XXXX集群节点信息"
- "查看XXXX集群最近1小时的CPU使用率"