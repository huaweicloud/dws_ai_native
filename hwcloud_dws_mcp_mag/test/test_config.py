import base64
import importlib
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import yaml
import pytest

from dws_autopilot_mcp.crypto import (
    _generate_master_key,
    _generate_nonce,
    encrypt_value,
    encrypt_master_key,
    save_crypt_json,
    generate_crypt_json_path,
    decrypt_value,
)


def _write_yaml(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _read_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class TestFindConfigPath:
    def test_env_var_set_and_file_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {"region_id": "test-region"})
            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                from dws_autopilot_mcp.config import _find_config_path
                result = _find_config_path()
                assert result == yaml_path

    def test_env_var_set_but_file_not_exists(self):
        with patch.dict(os.environ, {"DWS_MCP_CONFIG": "/nonexistent/dws_config.yaml"}):
            from dws_autopilot_mcp.config import _find_config_path
            with patch.object(Path, "exists", return_value=False):
                result = _find_config_path()
                assert result is None

    def test_no_env_var_uses_pkg_root(self):
        with patch.dict(os.environ, {}, clear=True):
            from dws_autopilot_mcp.config import _find_config_path
            result = _find_config_path()
            if result is not None:
                assert result.name == "dws_config.yaml"

    def test_no_env_var_no_pkg_root_file(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(Path, "exists", return_value=False):
                from dws_autopilot_mcp.config import _find_config_path
                result = _find_config_path()
                assert result is None


class TestFindConfigDir:
    def test_with_config_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})
            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                from dws_autopilot_mcp.config import _find_config_dir
                result = _find_config_dir()
                assert result == Path(tmpdir)

    def test_without_config_path(self):
        with patch("dws_autopilot_mcp.config._find_config_path", return_value=None):
            from dws_autopilot_mcp.config import _find_config_dir
            result = _find_config_dir()
            assert result.name == "conf"


class TestLoadConfig:
    def test_file_not_found(self):
        with patch("dws_autopilot_mcp.config._find_config_path", return_value=None):
            from dws_autopilot_mcp.config import _load_config
            result = _load_config()
            assert result == {}

    def test_valid_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {"region_id": "cn-north-7"})
            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path):
                from dws_autopilot_mcp.config import _load_config
                result = _load_config()
                assert result["region_id"] == "cn-north-7"

    def test_invalid_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            with open(yaml_path, "w") as f:
                f.write("{{invalid yaml::")
            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path):
                from dws_autopilot_mcp.config import _load_config
                result = _load_config()
                assert result == {}

    def test_empty_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})
            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path):
                from dws_autopilot_mcp.config import _load_config
                result = _load_config()
                assert result == {}


class TestSaveConfig:
    def test_save_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})
            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path):
                from dws_autopilot_mcp.config import _save_config
                _save_config({"region_id": "cn-north-7"})
                result = _read_yaml(yaml_path)
                assert result["region_id"] == "cn-north-7"

    def test_save_no_config_path(self):
        with patch("dws_autopilot_mcp.config._find_config_path", return_value=None):
            from dws_autopilot_mcp.config import _save_config
            _save_config({"region_id": "cn-north-7"})

    def test_save_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path):
                from dws_autopilot_mcp.config import _save_config
                with patch("builtins.open", side_effect=PermissionError("denied")):
                    _save_config({"region_id": "cn-north-7"})


class TestHasPlaintextSecrets:
    def test_with_plaintext_iam_password(self):
        from dws_autopilot_mcp.config import _has_plaintext_secrets
        cfg = {"iam": {"password": "mock_***_value"}}
        assert _has_plaintext_secrets(cfg) is True

    def test_with_plaintext_token(self):
        from dws_autopilot_mcp.config import _has_plaintext_secrets
        cfg = {"dws_mcp_token": "mock_***_token"}
        assert _has_plaintext_secrets(cfg) is True

    def test_with_crypter_already_set(self):
        from dws_autopilot_mcp.config import _has_plaintext_secrets
        cfg = {"iam": {"password": "mock_***_value"}, "encrypt": {"crypter": "xxx"}}
        assert _has_plaintext_secrets(cfg) is False

    def test_empty_secrets(self):
        from dws_autopilot_mcp.config import _has_plaintext_secrets
        cfg = {"iam": {"password": ""}, "dws_mcp_token": ""}
        assert _has_plaintext_secrets(cfg) is False

    def test_no_iam_section(self):
        from dws_autopilot_mcp.config import _has_plaintext_secrets
        cfg = {"dws_mcp_token": ""}
        assert _has_plaintext_secrets(cfg) is False


class TestAutoEncrypt:
    def test_encrypt_password_and_token(self):
        from dws_autopilot_mcp.config import _auto_encrypt

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})

            cfg = {
                "iam": {"password": "mock_***_pwd"},
                "dws_mcp_token": "mock_***_token",
            }

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _auto_encrypt(cfg)

            assert result["iam"]["password"] != "mock_***_pwd"
            assert result["dws_mcp_token"] != "mock_***_token"
            assert "encrypt" in result
            assert "crypter" in result["encrypt"]
            assert "nonce" in result["encrypt"]

            from dws_autopilot_mcp.crypto import recover_master_key as _recover, decrypt_value as _decrypt
            master_key = _recover(
                result["encrypt"]["crypter"],
                generate_crypt_json_path(Path(tmpdir)),
            )
            nonce = base64.b64decode(result["encrypt"]["nonce"])
            assert _decrypt(result["iam"]["password"], master_key, nonce) == "mock_***_pwd"
            assert _decrypt(result["dws_mcp_token"], master_key, nonce) == "mock_***_token"

    def test_encrypt_password_only(self):
        from dws_autopilot_mcp.config import _auto_encrypt

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})

            cfg = {"iam": {"password": "mock_***_pwd"}, "dws_mcp_token": ""}

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _auto_encrypt(cfg)

            assert result["iam"]["password"] != "mock_***_pwd"
            assert result["dws_mcp_token"] == ""
            assert "encrypt" in result

    def test_encrypt_token_only(self):
        from dws_autopilot_mcp.config import _auto_encrypt

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})

            cfg = {"iam": {}, "dws_mcp_token": "mock_***_token"}

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _auto_encrypt(cfg)

            assert result["dws_mcp_token"] != "mock_***_token"
            assert "encrypt" in result

    def test_encrypt_no_iam_section(self):
        from dws_autopilot_mcp.config import _auto_encrypt

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})

            cfg = {"dws_mcp_token": "mock_***_token"}

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _auto_encrypt(cfg)

            assert result["dws_mcp_token"] != "mock_***_token"
            assert "iam" in result

    def test_encrypt_import_error(self):
        from dws_autopilot_mcp.config import _auto_encrypt

        cfg = {"iam": {"password": "mock_***_pwd"}, "dws_mcp_token": "mock_***_token"}

        with patch("dws_autopilot_mcp.config._find_config_path", return_value=None), \
             patch.dict("sys.modules", {"dws_autopilot_mcp.crypto": None}):
            result = _auto_encrypt(cfg)

        assert result == cfg

    def test_encrypt_saves_yaml_and_crypt_json(self):
        from dws_autopilot_mcp.config import _auto_encrypt

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {})

            cfg = {"iam": {"password": "mock_***_pwd"}, "dws_mcp_token": ""}

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                _auto_encrypt(cfg)

            saved = _read_yaml(yaml_path)
            assert "encrypt" in saved
            assert saved["iam"]["password"] != "mock_***_pwd"

            crypt_json_path = generate_crypt_json_path(Path(tmpdir))
            assert crypt_json_path.exists()


class TestTryDecryptFields:
    def test_no_encrypt_section(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields
        cfg = {"iam": {"password": "mock_***_pwd"}, "dws_mcp_token": "mock_***_token"}
        result = _try_decrypt_fields(cfg)
        assert result == cfg

    def test_decrypt_encrypted_fields(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            master_key = _generate_master_key()
            nonce = _generate_nonce()
            crypter, crypt_component = encrypt_master_key(master_key)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

            enc_password = encrypt_value("mock_***_pwd", master_key, nonce)
            enc_token = encrypt_value("mock_***_token", master_key, nonce)

            save_crypt_json(generate_crypt_json_path(Path(tmpdir)), crypt_component)

            cfg = {
                "iam": {"password": enc_password},
                "dws_mcp_token": enc_token,
                "encrypt": {"crypter": crypter, "nonce": nonce_b64},
            }

            with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _try_decrypt_fields(cfg)

            assert result["iam"]["password"] == "mock_***_pwd"
            assert result["dws_mcp_token"] == "mock_***_token"

    def test_decrypt_password_only(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            master_key = _generate_master_key()
            nonce = _generate_nonce()
            crypter, crypt_component = encrypt_master_key(master_key)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

            enc_password = encrypt_value("mock_***_pwd", master_key, nonce)

            save_crypt_json(generate_crypt_json_path(Path(tmpdir)), crypt_component)

            cfg = {
                "iam": {"password": enc_password},
                "dws_mcp_token": "",
                "encrypt": {"crypter": crypter, "nonce": nonce_b64},
            }

            with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _try_decrypt_fields(cfg)

            assert result["iam"]["password"] == "mock_***_pwd"
            assert result["dws_mcp_token"] == ""

    def test_decrypt_token_only(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            master_key = _generate_master_key()
            nonce = _generate_nonce()
            crypter, crypt_component = encrypt_master_key(master_key)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

            enc_token = encrypt_value("mock_***_token", master_key, nonce)

            save_crypt_json(generate_crypt_json_path(Path(tmpdir)), crypt_component)

            cfg = {
                "iam": {"password": ""},
                "dws_mcp_token": enc_token,
                "encrypt": {"crypter": crypter, "nonce": nonce_b64},
            }

            with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _try_decrypt_fields(cfg)

            assert result["iam"]["password"] == ""
            assert result["dws_mcp_token"] == "mock_***_token"

    def test_decrypt_master_key_recovery_fails(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        cfg = {
            "iam": {"password": "some_ciphertext"},
            "dws_mcp_token": "some_ciphertext",
            "encrypt": {"crypter": "invalid-crypter", "nonce": base64.b64encode(b"0" * 12).decode()},
        }

        with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path("/nonexistent")):
            result = _try_decrypt_fields(cfg)

        assert result == cfg

    def test_decrypt_import_error(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        cfg = {
            "iam": {"password": "some_ciphertext"},
            "encrypt": {"crypter": "xxx", "nonce": "yyy"},
        }

        with patch.dict("sys.modules", {"dws_autopilot_mcp.crypto": None}):
            result = _try_decrypt_fields(cfg)

        assert result == cfg

    def test_decrypt_password_failure(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            master_key = _generate_master_key()
            nonce = _generate_nonce()
            crypter, crypt_component = encrypt_master_key(master_key)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

            save_crypt_json(generate_crypt_json_path(Path(tmpdir)), crypt_component)

            cfg = {
                "iam": {"password": "invalid-ciphertext"},
                "dws_mcp_token": "",
                "encrypt": {"crypter": crypter, "nonce": nonce_b64},
            }

            with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _try_decrypt_fields(cfg)

            assert result["iam"]["password"] == "invalid-ciphertext"

    def test_decrypt_token_failure(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            master_key = _generate_master_key()
            nonce = _generate_nonce()
            crypter, crypt_component = encrypt_master_key(master_key)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

            save_crypt_json(generate_crypt_json_path(Path(tmpdir)), crypt_component)

            cfg = {
                "iam": {"password": ""},
                "dws_mcp_token": "invalid-ciphertext",
                "encrypt": {"crypter": crypter, "nonce": nonce_b64},
            }

            with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _try_decrypt_fields(cfg)

            assert result["dws_mcp_token"] == "invalid-ciphertext"

    def test_decrypt_no_iam_section(self):
        from dws_autopilot_mcp.config import _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            master_key = _generate_master_key()
            nonce = _generate_nonce()
            crypter, crypt_component = encrypt_master_key(master_key)
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

            enc_token = encrypt_value("mock_***_token", master_key, nonce)

            save_crypt_json(generate_crypt_json_path(Path(tmpdir)), crypt_component)

            cfg = {
                "dws_mcp_token": enc_token,
                "encrypt": {"crypter": crypter, "nonce": nonce_b64},
            }

            with patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                result = _try_decrypt_fields(cfg)

            assert result["dws_mcp_token"] == "mock_***_token"


class TestConfigModuleLoad:
    def test_auto_encrypt_then_decrypt_roundtrip(self):
        from dws_autopilot_mcp.config import _load_config, _has_plaintext_secrets, _auto_encrypt, _try_decrypt_fields

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {
                "region_id": "cn-north-7",
                "iam": {"username": "mock_user", "password": "mock_***_pwd", "domain_name": "", "project_id": ""},
                "dws_mcp_token": "mock_***_token",
            })

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                cfg = _load_config()
                assert _has_plaintext_secrets(cfg) is True
                cfg = _auto_encrypt(cfg)
                assert _has_plaintext_secrets(cfg) is False

                result = _try_decrypt_fields(cfg)
                assert result["iam"]["password"] == "mock_***_pwd"
                assert result["dws_mcp_token"] == "mock_***_token"
                assert result["region_id"] == "cn-north-7"

            saved = _read_yaml(yaml_path)
            assert saved["iam"]["password"] != "mock_***_pwd"
            assert saved["dws_mcp_token"] != "mock_***_token"

            with patch("dws_autopilot_mcp.config._find_config_path", return_value=yaml_path), \
                 patch("dws_autopilot_mcp.config._find_config_dir", return_value=Path(tmpdir)):
                cfg2 = _load_config()
                assert _has_plaintext_secrets(cfg2) is False
                result2 = _try_decrypt_fields(cfg2)
                assert result2["iam"]["password"] == "mock_***_pwd"
                assert result2["dws_mcp_token"] == "mock_***_token"

    def test_region_id_generates_urls(self):
        cfg = {"region_id": "cn-north-7", "iam": {"password": ""}, "dws_mcp_token": ""}
        region_id = cfg.get("region_id", "")
        base_url = f"https://dws.{region_id}.myhuaweicloud.com" if region_id else ""
        iam_endpoint = f"https://iam.{region_id}.myhuaweicloud.com" if region_id else ""
        assert base_url == "https://dws.cn-north-7.myhuaweicloud.com"
        assert iam_endpoint == "https://iam.cn-north-7.myhuaweicloud.com"

    def test_empty_region_id(self):
        cfg = {"region_id": "", "iam": {}, "dws_mcp_token": ""}
        region_id = cfg.get("region_id", "")
        base_url = f"https://dws.{region_id}.myhuaweicloud.com" if region_id else ""
        iam_endpoint = f"https://iam.{region_id}.myhuaweicloud.com" if region_id else ""
        assert base_url == ""
        assert iam_endpoint == ""

    def test_iam_mode_detection(self):
        cfg = {
            "region_id": "cn-north-7",
            "iam": {"username": "mock_user", "password": "mock_***_pwd", "domain_name": "", "project_id": ""},
            "dws_mcp_token": "",
        }
        region_id = cfg.get("region_id", "")
        iam_endpoint = f"https://iam.{region_id}.myhuaweicloud.com" if region_id else ""
        iam_username = cfg.get("iam", {}).get("username", "")
        iam_password = cfg.get("iam", {}).get("password", "")
        assert iam_endpoint and iam_username and iam_password

    def test_token_mode_detection(self):
        cfg = {
            "region_id": "cn-north-7",
            "iam": {"username": "", "password": "", "domain_name": "", "project_id": ""},
            "dws_mcp_token": "mock_***_token",
        }
        dws_mcp_token = cfg.get("dws_mcp_token", "")
        assert dws_mcp_token != ""

    def test_no_credentials(self):
        cfg = {"region_id": "cn-north-7", "iam": {"username": "", "password": ""}, "dws_mcp_token": ""}
        iam_endpoint = f"https://iam.cn-north-7.myhuaweicloud.com"
        iam_username = cfg.get("iam", {}).get("username", "")
        iam_password = cfg.get("iam", {}).get("password", "")
        dws_mcp_token = cfg.get("dws_mcp_token", "")
        assert not (iam_endpoint and iam_username and iam_password)
        assert not dws_mcp_token


class TestBuildProxyUrl:
    def test_empty_base_url(self):
        from dws_autopilot_mcp.config import _build_proxy_url
        with patch("dws_autopilot_mcp.config._PROXY_USERNAME", "user"):
            assert _build_proxy_url("") == ""

    def test_no_proxy_username(self):
        from dws_autopilot_mcp.config import _build_proxy_url
        with patch("dws_autopilot_mcp.config._PROXY_USERNAME", ""):
            assert _build_proxy_url("http://proxy.example.com:8080") == "http://proxy.example.com:8080"

    def test_with_proxy_username_and_port(self):
        from dws_autopilot_mcp.config import _build_proxy_url
        with patch("dws_autopilot_mcp.config._PROXY_USERNAME", "user"), \
             patch("dws_autopilot_mcp.config._PROXY_PASSWORD", "pass"):
            result = _build_proxy_url("http://proxy.example.com:8080")
            assert "user%40" in result or "user" in result
            assert "@proxy.example.com" in result
            assert ":8080" in result

    def test_with_proxy_username_no_port(self):
        from dws_autopilot_mcp.config import _build_proxy_url
        with patch("dws_autopilot_mcp.config._PROXY_USERNAME", "user"), \
             patch("dws_autopilot_mcp.config._PROXY_PASSWORD", "pass"):
            result = _build_proxy_url("http://proxy.example.com")
            assert "@proxy.example.com" in result
            assert ":8080" not in result

    def test_special_chars_percent_encoded(self):
        from dws_autopilot_mcp.config import _build_proxy_url
        with patch("dws_autopilot_mcp.config._PROXY_USERNAME", "user@domain"), \
             patch("dws_autopilot_mcp.config._PROXY_PASSWORD", "p@ss:word"):
            result = _build_proxy_url("http://proxy.example.com:8080")
            assert "user%40domain" in result
            assert "p%40ss%3Aword" in result


class TestModuleLevelCode:
    def test_auto_encrypt_on_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {
                "region_id": "cn-north-7",
                "iam": {"username": "mock_user", "password": "mock_***_pwd", "domain_name": "mock_domain", "project_id": "mock_proj"},
                "dws_mcp_token": "",
            })

            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                import dws_autopilot_mcp.config as cfg_mod
                importlib.reload(cfg_mod)

                assert cfg_mod.REGION_ID == "cn-north-7"
                assert cfg_mod.DMS_MONITORING_BASE_URL == "https://dws.cn-north-7.myhuaweicloud.com"
                assert cfg_mod.IAM_ENDPOINT == "https://iam.cn-north-7.myhuaweicloud.com"
                assert cfg_mod.IAM_USERNAME == "mock_user"
                assert cfg_mod.IAM_PASSWORD == "mock_***_pwd"
                assert cfg_mod.IAM_DOMAIN_NAME == "mock_domain"
                assert cfg_mod.IAM_PROJECT_ID == "mock_proj"

                saved = _read_yaml(yaml_path)
                assert "encrypt" in saved
                assert saved["iam"]["password"] != "mock_***_pwd"

    def test_static_token_mode_on_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {
                "region_id": "cn-north-7",
                "iam": {"username": "", "password": "", "domain_name": "", "project_id": ""},
                "dws_mcp_token": "mock_***_static_token",
            })

            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                import dws_autopilot_mcp.config as cfg_mod
                importlib.reload(cfg_mod)

                assert cfg_mod.DWS_MCP_TOKEN == "mock_***_static_token"
                assert cfg_mod.IAM_USERNAME == ""
                assert cfg_mod.IAM_PASSWORD == ""

    def test_no_credentials_warning_on_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {
                "region_id": "cn-north-7",
                "iam": {"username": "", "password": "", "domain_name": "", "project_id": ""},
                "dws_mcp_token": "",
            })

            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                import dws_autopilot_mcp.config as cfg_mod
                importlib.reload(cfg_mod)

                assert cfg_mod.DWS_MCP_TOKEN == ""
                assert cfg_mod.IAM_USERNAME == ""
                assert cfg_mod.IAM_PASSWORD == ""

    def test_empty_region_id_on_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {
                "region_id": "",
                "iam": {"username": "", "password": "", "domain_name": "", "project_id": ""},
                "dws_mcp_token": "",
            })

            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                import dws_autopilot_mcp.config as cfg_mod
                importlib.reload(cfg_mod)

                assert cfg_mod.REGION_ID == ""
                assert cfg_mod.DMS_MONITORING_BASE_URL == ""
                assert cfg_mod.IAM_ENDPOINT == ""

    def test_proxy_configured_on_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_path = Path(tmpdir) / "dws_config.yaml"
            _write_yaml(yaml_path, {
                "region_id": "cn-7",
                "http_proxy": "http://proxy.example.com:8080",
                "https_proxy": "https://proxy.example.com:8443",
                "iam": {"username": "", "password": "", "domain_name": "", "project_id": ""},
                "dws_mcp_token": "static-tok",
            })

            with patch.dict(os.environ, {"DWS_MCP_CONFIG": str(yaml_path)}):
                import dws_autopilot_mcp.config as cfg_mod
                importlib.reload(cfg_mod)

                assert cfg_mod.HTTP_PROXY != ""
                assert cfg_mod.HTTPS_PROXY != ""
