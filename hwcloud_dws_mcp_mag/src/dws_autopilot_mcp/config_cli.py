import argparse
import logging
import os
import sys
from pathlib import Path

import yaml

logging.getLogger("dws_autopilot_mcp").setLevel(logging.ERROR)
logger = logging.getLogger("dws_autopilot_mcp.config_cli")

from .crypto import (
    _generate_master_key,
    _generate_nonce,
    encrypt_value,
    encrypt_master_key,
    decrypt_value,
    recover_master_key,
    save_crypt_json,
    generate_crypt_json_path,
)
from .config import _find_config_path, _find_config_dir, _load_config

import base64


def _read_yaml(path: Path) -> dict:
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _write_yaml(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


_EMPTY_CONFIG = {
    "region_id": "",
    "iam": {
        "username": "",
        "password": "",
        "domain_name": "",
        "project_id": "",
    },
    "dws_mcp_token": "",
    "http_proxy": "",
    "https_proxy": "",
    "proxy_username": "",
    "proxy_password": "",
}


def _decrypt_cfg_if_needed(cfg: dict) -> dict:
    encrypt_section = cfg.get("encrypt", {})
    crypter = encrypt_section.get("crypter", "")
    nonce_b64 = encrypt_section.get("nonce", "")

    if not crypter or not nonce_b64:
        return cfg

    config_dir = _find_config_dir()
    crypt_json_path = generate_crypt_json_path(config_dir)
    master_key = recover_master_key(crypter, crypt_json_path)
    if master_key is None:
        print("Warning: Failed to recover master key, treating values as plaintext")
        return cfg

    nonce = base64.b64decode(nonce_b64)
    result = dict(cfg)

    encrypted_password = result.get("iam", {}).get("password", "")
    if encrypted_password:
        try:
            result["iam"] = dict(result.get("iam", {}))
            result["iam"]["password"] = decrypt_value(encrypted_password, master_key, nonce)
        except Exception as e:
            logger.warning("Failed to decrypt iam.password: %s", e)
            result["iam"]["password"] = ""

    encrypted_token = result.get("dws_mcp_token", "")
    if encrypted_token:
        try:
            result["dws_mcp_token"] = decrypt_value(encrypted_token, master_key, nonce)
        except Exception as e:
            logger.warning("Failed to decrypt dws_mcp_token: %s", e)
            result["dws_mcp_token"] = ""

    return result


def cmd_init(args) -> None:
    config_path = _find_config_path()
    if config_path is None:
        config_dir = _find_config_dir()
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "dws_config.yaml"

    cfg = _read_yaml(config_path)
    cfg = _decrypt_cfg_if_needed(cfg)
    if "encrypt" in cfg:
        del cfg["encrypt"]

    cfg.setdefault("iam", {})

    if args.region_id is not None:
        cfg["region_id"] = args.region_id
    if args.username is not None:
        cfg["iam"]["username"] = args.username
    if args.password is not None:
        cfg["iam"]["password"] = args.password
    if args.domain_name is not None:
        cfg["iam"]["domain_name"] = args.domain_name
    if args.project_id is not None:
        cfg["iam"]["project_id"] = args.project_id
    if args.token is not None:
        cfg["dws_mcp_token"] = args.token
    if args.http_proxy is not None:
        cfg["http_proxy"] = args.http_proxy
    if args.https_proxy is not None:
        cfg["https_proxy"] = args.https_proxy
    if args.proxy_username is not None:
        cfg["proxy_username"] = args.proxy_username
    if args.proxy_password is not None:
        cfg["proxy_password"] = args.proxy_password

    _write_yaml(config_path, cfg)
    print(f"Config saved to {config_path}")
    print("Restart MCP server to auto-encrypt sensitive fields.")


def cmd_encrypt(args) -> None:
    config_path = _find_config_path()
    if config_path is None:
        print("dws_config.yaml not found.")
        sys.exit(1)

    cfg = _read_yaml(config_path)

    if cfg.get("encrypt", {}).get("crypter"):
        print("Already encrypted. Use 'reset' or 'init' to update values first.")
        return

    password = cfg.get("iam", {}).get("password", "")
    token = cfg.get("dws_mcp_token", "")

    if not password and not token:
        print("No plaintext sensitive fields found. Nothing to encrypt.")
        return

    master_key = _generate_master_key()
    nonce = _generate_nonce()

    result = dict(cfg)
    result.setdefault("iam", {})

    if password:
        result["iam"] = dict(result.get("iam", {}))
        result["iam"]["password"] = encrypt_value(password, master_key, nonce)
        print("Encrypted iam.password")

    if token:
        result["dws_mcp_token"] = encrypt_value(token, master_key, nonce)
        print("Encrypted dws_mcp_token")

    crypter, crypt_component = encrypt_master_key(master_key)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    result["encrypt"] = {
        "crypter": crypter,
        "nonce": nonce_b64,
    }

    _write_yaml(config_path, result)

    config_dir = _find_config_dir()
    crypt_json_path = generate_crypt_json_path(config_dir)
    save_crypt_json(crypt_json_path, crypt_component)
    print(f"Saved crypto.json to {crypt_json_path}")
    print("Encryption complete.")


def cmd_reset(args) -> None:
    config_path = _find_config_path()
    if config_path is None:
        config_dir = _find_config_dir()
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "dws_config.yaml"

    _write_yaml(config_path, dict(_EMPTY_CONFIG))
    print(f"Reset {config_path} to empty template.")

    config_dir = _find_config_dir()
    crypt_json_path = generate_crypt_json_path(config_dir)
    if crypt_json_path.exists():
        crypt_json_path.unlink()
        print(f"Removed {crypt_json_path}")

    print("Use 'dws-mcp-config init' to set new values.")


def cmd_show(args) -> None:
    config_path = _find_config_path()
    if config_path is None:
        print("dws_config.yaml not found.")
        return

    cfg = _load_config()
    encrypt_section = cfg.get("encrypt", {})

    region_id = cfg.get("region_id", "")
    username = cfg.get("iam", {}).get("username", "")
    domain_name = cfg.get("iam", {}).get("domain_name", "")
    project_id = cfg.get("iam", {}).get("project_id", "")
    has_password = bool(cfg.get("iam", {}).get("password", ""))
    has_token = bool(cfg.get("dws_mcp_token", ""))
    is_encrypted = bool(encrypt_section.get("crypter"))

    print(f"Config file: {config_path}")
    print(f"region_id:   {region_id or '(empty)'}")
    print(f"username:    {username or '(empty)'}")
    print(f"domain_name: {domain_name or '(empty)'}")
    print(f"project_id:  {project_id or '(empty)'}")
    print(f"password:    {'****** (encrypted)' if is_encrypted and has_password else '******' if has_password else '(empty)'}")
    print(f"token:       {'****** (encrypted)' if is_encrypted and has_token else '******' if has_token else '(empty)'}")
    print(f"encrypted:   {'Yes' if is_encrypted else 'No'}")

    http_proxy = cfg.get("http_proxy", "")
    https_proxy = cfg.get("https_proxy", "")
    proxy_username = cfg.get("proxy_username", "")
    has_proxy_password = bool(cfg.get("proxy_password", ""))
    print(f"http_proxy:      {http_proxy or '(empty, will use system proxy)'}")
    print(f"https_proxy:     {https_proxy or '(empty, will use system proxy)'}")
    print(f"proxy_username:  {proxy_username or '(empty)'}")
    print(f"proxy_password:  {'******' if has_proxy_password else '(empty)'}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dws-mcp-config",
        description="Manage dws_config.yaml configuration",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize or update config values")
    init_parser.add_argument("--region_id", help="Region ID, e.g. cn-north-7")
    init_parser.add_argument("--username", help="IAM username")
    init_parser.add_argument("--password", help="IAM password")
    init_parser.add_argument("--domain_name", help="IAM domain name (account name)")
    init_parser.add_argument("--project_id", help="IAM project ID")
    init_parser.add_argument("--token", help="DWS MCP static token (alternative to IAM)")
    init_parser.add_argument("--http_proxy", help="HTTP proxy base URL, e.g. http://proxy:port (without credentials)")
    init_parser.add_argument("--https_proxy", help="HTTPS proxy base URL, e.g. https://proxy:port (without credentials)")
    init_parser.add_argument("--proxy_username", help="Proxy authentication username")
    init_parser.add_argument("--proxy_password", help="Proxy authentication password (special chars are auto-encoded)")

    subparsers.add_parser("encrypt", help="Encrypt plaintext password and token in config")
    subparsers.add_parser("reset", help="Reset config to empty template and remove crypto.json")
    subparsers.add_parser("show", help="Show current config status (no secrets revealed)")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "reset":
        cmd_reset(args)
    elif args.command == "show":
        cmd_show(args)


if __name__ == "__main__":
    main()
