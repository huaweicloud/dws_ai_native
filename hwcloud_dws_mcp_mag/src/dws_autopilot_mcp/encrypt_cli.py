import argparse
import importlib
import sys
from pathlib import Path

import yaml

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


def _find_config_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "conf"


def _load_yaml(path: Path) -> dict:
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _save_yaml(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def cmd_encrypt(args) -> None:
    config_dir = _find_config_dir()
    config_path = config_dir / "dws_config.yaml"

    cfg = _load_yaml(config_path)

    plaintext_ak = cfg.get("ak", "")
    plaintext_sk = cfg.get("sk", "")

    if not plaintext_ak and not plaintext_sk:
        print("No plaintext ak or sk found in dws_config.yaml. Nothing to encrypt.")
        return

    if cfg.get("encrypt", {}).get("crypter"):
        print("Encrypted values already exist. Remove encrypt section first to re-encrypt.")
        return

    master_key = _generate_master_key()
    nonce = _generate_nonce()

    enc_cfg = cfg.copy()

    if plaintext_ak:
        enc_cfg["ak"] = encrypt_value(plaintext_ak, master_key, nonce)
        print("Encrypted ak")

    if plaintext_sk:
        enc_cfg["sk"] = encrypt_value(plaintext_sk, master_key, nonce)
        print("Encrypted sk")

    crypter, crypt_component = encrypt_master_key(master_key)
    base64 = importlib.import_module("base64")
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    enc_cfg["encrypt"] = {
        "crypter": crypter,
        "nonce": nonce_b64,
    }

    _save_yaml(config_path, enc_cfg)
    print(f"Updated dws_config.yaml with encrypted values")

    crypt_json_path = generate_crypt_json_path(config_dir)
    save_crypt_json(crypt_json_path, crypt_component)
    print(f"Saved crypto.json to {crypt_json_path}")


def cmd_decrypt(args) -> None:
    config_dir = _find_config_dir()
    config_path = config_dir / "dws_config.yaml"

    cfg = _load_yaml(config_path)

    encrypt_section = cfg.get("encrypt", {})
    crypter = encrypt_section.get("crypter", "")
    nonce_b64 = encrypt_section.get("nonce", "")

    if not crypter or not nonce_b64:
        print("No encrypted values found in dws_config.yaml.")
        return

    import base64
    nonce = base64.b64decode(nonce_b64)

    crypt_json_path = generate_crypt_json_path(config_dir)
    master_key = recover_master_key(crypter, crypt_json_path)
    if master_key is None:
        print("Failed to recover master key. Are you on the same machine where encryption was done?")
        sys.exit(1)

    enc_cfg = cfg.copy()

    encrypted_ak = cfg.get("ak", "")
    encrypted_sk = cfg.get("sk", "")

    if encrypted_ak:
        try:
            enc_cfg["ak"] = decrypt_value(encrypted_ak, master_key, nonce)
            print("Decrypted ak")
        except Exception as e:
            print(f"Failed to decrypt ak: {e}")

    if encrypted_sk:
        try:
            enc_cfg["sk"] = decrypt_value(encrypted_sk, master_key, nonce)
            print("Decrypted sk")
        except Exception as e:
            print(f"Failed to decrypt sk: {e}")

    del enc_cfg["encrypt"]

    _save_yaml(config_path, enc_cfg)
    print(f"Updated dws_config.yaml with plaintext values")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dws-mcp-encrypt",
        description="Encrypt/decrypt sensitive fields in dws_config.yaml",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("encrypt", help="Encrypt ak and sk in dws_config.yaml")
    subparsers.add_parser("decrypt", help="Decrypt ak and sk in dws_config.yaml")

    args = parser.parse_args()

    if args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)


if __name__ == "__main__":
    main()
