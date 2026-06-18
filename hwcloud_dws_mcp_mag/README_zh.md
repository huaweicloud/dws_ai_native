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

1. **dws_service_autopilot_host_overview**
   查询DWS集群节点信息，支持按主机名/IP过滤、分页、排序

2. **get_metric_data_list**
   查询DWS集群指标数据，支持 cpu_usage、mem_usage、disk_usage_avg、tcp_resend_rate、disk_io、net_io 等指标

### 2.2 认证方式
支持两种认证方式（优先级从高到低）：

1. **IAM 动态 Token 模式**：通过 IAM 用户名/密码自动获取临时 Token，推荐使用
2. **静态 Token 模式**：直接配置 `dws_mcp_token`，适用于已有 Token 的场景

### 2.3 配置加密
敏感字段（IAM 密码、MCP Token）支持 AES-256-GCM 加密存储：
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
iam:
  username: "your_iam_username"
  password: "your_iam_password"
  domain_name: "your_domain_name"
  project_id: "your_project_id"
dws_mcp_token: ""
```

**参数说明：**

| 参数 | 说明 | 示例 |
|------|------|------|
| `region_id` | 华为云区域ID，用于自动生成 API 端点 | `cn-north-7` |
| `iam.username` | IAM 用户名 | - |
| `iam.password` | IAM 密码（明文输入，启动后自动加密） | - |
| `iam.domain_name` | IAM 域名（账号名） | - |
| `iam.project_id` | IAM 项目ID | - |
| `dws_mcp_token` | 静态 Token（与 IAM 二选一，明文输入启动后自动加密） | - |

> `region_id` 会自动生成 `DMS_MONITORING_BASE_URL`（`https://dws.{region_id}.myhuaweicloud.com`）和 `IAM_ENDPOINT`（`https://iam.{region_id}.myhuaweicloud.com`），无需手动配置。

> 也可通过环境变量 `DWS_MCP_CONFIG` 指定配置文件路径。

### 3.4 配置管理CLI
安装后提供 `dws-mcp-config` 命令行工具，需在项目根目录（`dws_autopilot_mcp/`）下执行：

#### init - 初始化/更新配置
`init` 命令用于设置配置参数，支持两种认证方式（二选一）：

**方式一：IAM 动态 Token（推荐）**
```bash
python -m dws_autopilot_mcp.config_cli init --region_id cn-north-7 --username admin --password xxx --domain_name xxx --project_id xxx
```
通过 IAM 用户名/密码自动获取临时 Token，Token 自动续期，无需手动维护。

**方式二：静态 Token**
```bash
python -m dws_autopilot_mcp.config_cli init --region_id cn-north-7 --token your_token
```
直接使用已有的 Token，适用于已获取 Token 的场景。

> 两种方式的区别仅在于认证参数不同：方式一需提供 `--username`、`--password`、`--domain_name`、`--project_id`，方式二只需提供 `--token`。`--region_id` 为必填参数，两种方式均需提供。
>
> `init` 命令支持部分更新，仅更新指定的参数，未指定的参数保持不变。例如只更新密码：`python -m dws_autopilot_mcp.config_cli init --password new_password`。
>
> 更新配置后，重启 MCP Server 即可自动加密敏感字段（password、token）。

#### 其他命令

```bash
# 手动触发加密（将明文敏感字段加密，启动MCP Server时也会自动执行）
python -m dws_autopilot_mcp.config_cli encrypt

# 查看配置状态（敏感信息以 ****** 显示，不会泄露）
python -m dws_autopilot_mcp.config_cli show

# 重置配置为空模板（清空所有参数，删除 crypt.json）
python -m dws_autopilot_mcp.config_cli reset
```

> `encrypt`、`show`、`reset` 命令无需额外参数，与认证方式无关，两种模式下通用。

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

> 将 `/path/to/python.exe` 替换为本机 Python 可执行文件路径，`/path/to/dws_autopilot_mcp/src` 替换为本项目 `src` 目录的绝对路径。

## 4. 开始体验
完成配置后，即可在客户端中通过自然语言与 DWS 集群交互，例如：
- "查询XXXX集群节点信息"
- "查看XXXX集群最近1小时的CPU使用率"