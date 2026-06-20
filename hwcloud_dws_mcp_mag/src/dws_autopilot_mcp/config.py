import os
import base64
import logging
from pathlib import Path

import yaml

logger = logging.getLogger("dws_autopilot_mcp")


def _find_config_path() -> Path | None:
    env_path = os.environ.get("DWS_MCP_CONFIG", "")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    pkg_root_path = Path(__file__).resolve().parent.parent.parent / "conf" / "dws_config.yaml"
    if pkg_root_path.exists():
        return pkg_root_path

    return None


def _find_config_dir() -> Path:
    config_path = _find_config_path()
    if config_path is not None:
        return config_path.parent
    return Path(__file__).resolve().parent.parent.parent / "conf"


def _load_config() -> dict:
    config_path = _find_config_path()
    if config_path is None:
        logger.info("dws_config.yaml not found, using default empty values")
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Failed to load dws_config.yaml: %s", e)
        return {}


def _save_config(cfg: dict) -> None:
    config_path = _find_config_path()
    if config_path is None:
        return
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    except Exception as e:
        logger.warning("Failed to save dws_config.yaml: %s", e)


def _has_plaintext_secrets(cfg: dict) -> bool:
    if cfg.get("encrypt", {}).get("crypter"):
        return False
    password = cfg.get("iam", {}).get("password", "")
    token = cfg.get("dws_mcp_token", "")
    return bool(password) or bool(token)


def _auto_encrypt(cfg: dict) -> dict:
    try:
        from .crypto import (
            _generate_master_key,
            _generate_nonce,
            encrypt_value,
            encrypt_master_key,
            save_crypt_json,
            generate_crypt_json_path,
        )
    except ImportError:
        logger.warning("cryptography package not installed, cannot auto-encrypt sensitive values")
        return cfg

    master_key = _generate_master_key()
    nonce = _generate_nonce()

    result = dict(cfg)
    result.setdefault("iam", {})

    password = result["iam"].get("password", "")
    if password:
        result["iam"] = dict(result["iam"])
        result["iam"]["password"] = encrypt_value(password, master_key, nonce)
        logger.info("Auto-encrypted iam.password")

    token = result.get("dws_mcp_token", "")
    if token:
        result["dws_mcp_token"] = encrypt_value(token, master_key, nonce)
        logger.info("Auto-encrypted dws_mcp_token")

    crypter, crypt_component = encrypt_master_key(master_key)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    result["encrypt"] = {
        "crypter": crypter,
        "nonce": nonce_b64,
    }

    _save_config(result)

    config_dir = _find_config_dir()
    crypt_json_path = generate_crypt_json_path(config_dir)
    save_crypt_json(crypt_json_path, crypt_component)
    logger.info("Saved crypto.json to %s", crypt_json_path)

    return result


def _try_decrypt_fields(cfg: dict) -> dict:
    encrypt_section = cfg.get("encrypt", {})
    crypter = encrypt_section.get("crypter", "")
    nonce_b64 = encrypt_section.get("nonce", "")

    if not crypter or not nonce_b64:
        return cfg

    try:
        from .crypto import recover_master_key, decrypt_value, generate_crypt_json_path

        nonce = base64.b64decode(nonce_b64)
        config_dir = _find_config_dir()
        crypt_json_path = generate_crypt_json_path(config_dir)

        master_key = recover_master_key(crypter, crypt_json_path)
        if master_key is None:
            logger.warning("Failed to recover master key, encrypted values will remain encrypted")
            return cfg

        result = dict(cfg)

        encrypted_password = result.get("iam", {}).get("password", "")
        if encrypted_password:
            try:
                result["iam"] = dict(result.get("iam", {}))
                result["iam"]["password"] = decrypt_value(encrypted_password, master_key, nonce)
            except Exception as e:
                logger.warning("Failed to decrypt iam.password: %s", e)

        encrypted_token = result.get("dws_mcp_token", "")
        if encrypted_token:
            try:
                result["dws_mcp_token"] = decrypt_value(encrypted_token, master_key, nonce)
            except Exception as e:
                logger.warning("Failed to decrypt dws_mcp_token: %s", e)

        return result
    except ImportError:
        logger.warning("cryptography package not installed, cannot decrypt encrypted values")
        return cfg


_cfg = _load_config()

if _has_plaintext_secrets(_cfg):
    logger.info("Detected plaintext sensitive fields, auto-encrypting...")
    _cfg = _auto_encrypt(_cfg)

_cfg = _try_decrypt_fields(_cfg)

_PROXY_USERNAME = _cfg.get("proxy_username", "")
_PROXY_PASSWORD = _cfg.get("proxy_password", "")


def _build_proxy_url(base_url: str) -> str:
    """Inject proxy_username:proxy_password into base_url with proper percent-encoding."""
    if not base_url:
        return ""
    if not _PROXY_USERNAME:
        return base_url
    from urllib.parse import urlparse, quote, urlunparse

    parsed = urlparse(base_url)
    encoded_auth = f"{quote(_PROXY_USERNAME, safe='')}:{quote(_PROXY_PASSWORD, safe='')}"
    netloc = f"{encoded_auth}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


_HTTP_PROXY_BASE = _cfg.get("http_proxy", "")
_HTTPS_PROXY_BASE = _cfg.get("https_proxy", "")

HTTP_PROXY = _build_proxy_url(_HTTP_PROXY_BASE)
HTTPS_PROXY = _build_proxy_url(_HTTPS_PROXY_BASE)

REGION_ID = _cfg.get("region_id", "")

DMS_MONITORING_BASE_URL = f"https://dws.{REGION_ID}.myhuaweicloud.com" if REGION_ID else ""

if not DMS_MONITORING_BASE_URL:
    logger.warning(
        "DMS_MONITORING_BASE_URL is not set. Please configure region_id in conf/dws_config.yaml."
    )

DWS_MCP_TOKEN = _cfg.get("dws_mcp_token", "")

if not DWS_MCP_TOKEN:
    logger.warning(
        "DWS_MCP_TOKEN is not set. API requests may fail with 401 Unauthorized. "
        "Please configure it in conf/dws_config.yaml."
    )

IAM_ENDPOINT = f"https://iam.{REGION_ID}.myhuaweicloud.com" if REGION_ID else ""
IAM_USERNAME = _cfg.get("iam", {}).get("username", "")
IAM_PASSWORD = _cfg.get("iam", {}).get("password", "")
IAM_DOMAIN_NAME = _cfg.get("iam", {}).get("domain_name", "")
IAM_PROJECT_ID = _cfg.get("iam", {}).get("project_id", "")

if HTTP_PROXY or HTTPS_PROXY:
    logger.info("Proxy configured: http_proxy=%s, https_proxy=%s", HTTP_PROXY or "(none)", HTTPS_PROXY or "(none)")

if IAM_ENDPOINT and IAM_USERNAME and IAM_PASSWORD:
    logger.info(
        "IAM dynamic token mode configured: endpoint=%s, username=%s",
        IAM_ENDPOINT,
        IAM_USERNAME,
    )
elif DWS_MCP_TOKEN:
    logger.info("Using static DWS_MCP_TOKEN mode")
else:
    logger.warning(
        "Neither IAM credentials nor DWS_MCP_TOKEN is configured. "
        "API requests may fail with 401."
    )