import argparse
import logging
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
    "ak": "",
    "sk": "",
    "project_id": "",
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

    encrypted_ak = result.get("ak", "")
    if encrypted_ak:
        try:
            result["ak"] = decrypt_value(encrypted_ak, master_key, nonce)
        except Exception as e:
            logger.warning("Failed to decrypt ak: %s", e)
            result["ak"] = ""

    encrypted_sk = result.get("sk", "")
    if encrypted_sk:
        try:
            result["sk"] = decrypt_value(encrypted_sk, master_key, nonce)
        except Exception as e:
            logger.warning("Failed to decrypt sk: %s", e)
            result["sk"] = ""

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

    if args.region_id is not None:
        cfg["region_id"] = args.region_id
    if args.ak is not None:
        cfg["ak"] = args.ak
    if args.sk is not None:
        cfg["sk"] = args.sk
    if args.project_id is not None:
        cfg["project_id"] = args.project_id
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

    ak = cfg.get("ak", "")
    sk = cfg.get("sk", "")

    if not ak and not sk:
        print("No plaintext sensitive fields found. Nothing to encrypt.")
        return

    master_key = _generate_master_key()
    nonce = _generate_nonce()

    result = dict(cfg)

    if ak:
        result["ak"] = encrypt_value(ak, master_key, nonce)
        print("Encrypted ak")

    if sk:
        result["sk"] = encrypt_value(sk, master_key, nonce)
        print("Encrypted sk")

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
    project_id = cfg.get("project_id", "")
    has_ak = bool(cfg.get("ak", ""))
    has_sk = bool(cfg.get("sk", ""))
    is_encrypted = bool(encrypt_section.get("crypter"))

    print(f"Config file: {config_path}")
    print(f"region_id:   {region_id or '(empty)'}")
    print(f"project_id:  {project_id or '(empty)'}")
    print(f"ak:          {'****** (encrypted)' if is_encrypted and has_ak else '******' if has_ak else '(empty)'}")
    print(f"sk:          {'****** (encrypted)' if is_encrypted and has_sk else '******' if has_sk else '(empty)'}")
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
    init_parser.add_argument("--ak", help="HUAWEICLOUD SDK AK (Access Key)")
    init_parser.add_argument("--sk", help="HUAWEICLOUD SDK SK (Secret Key)")
    init_parser.add_argument("--project_id", help="Project ID for X-Project-Id header")
    init_parser.add_argument("--http_proxy", help="HTTP proxy base URL, e.g. http://proxy:port (without credentials)")
    init_parser.add_argument("--https_proxy", help="HTTPS proxy base URL, e.g. https://proxy:port (without credentials)")
    init_parser.add_argument("--proxy_username", help="Proxy authentication username")
    init_parser.add_argument("--proxy_password", help="Proxy authentication password (special chars are auto-encoded)")

    subparsers.add_parser("encrypt", help="Encrypt plaintext ak and sk in config")
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
