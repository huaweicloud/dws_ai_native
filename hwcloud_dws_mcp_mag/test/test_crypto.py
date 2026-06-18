import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from dws_autopilot_mcp.crypto import (
    _generate_master_key,
    _generate_nonce,
    _get_machine_fingerprint,
    _split_key,
    _join_key,
    _encrypt_key_component,
    _decrypt_key_component,
    encrypt_value,
    decrypt_value,
    encrypt_master_key,
    decrypt_master_key_from_crypter,
    decrypt_master_key_from_component,
    recover_master_key,
    save_crypt_json,
    load_crypt_json,
    generate_crypt_json_path,
)


class TestMachineFingerprint:
    def test_returns_bytes(self):
        fp = _get_machine_fingerprint()
        assert isinstance(fp, bytes)
        assert len(fp) == 32

    def test_deterministic(self):
        fp1 = _get_machine_fingerprint()
        fp2 = _get_machine_fingerprint()
        assert fp1 == fp2

    def test_home_from_userprofile(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ["USERPROFILE"] = "C:\\Users\\testuser"
            os.environ["USERNAME"] = "testuser"
            os.environ["COMPUTERNAME"] = "MYPC"
            fp = _get_machine_fingerprint()
            assert os.environ["HOME"] == "C:\\Users\\testuser"
            assert isinstance(fp, bytes) and len(fp) == 32

    def test_home_from_homedrive_homepath(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ["HOMEDRIVE"] = "C:"
            os.environ["HOMEPATH"] = "\\Users\\testuser"
            os.environ["USERNAME"] = "testuser"
            os.environ["COMPUTERNAME"] = "MYPC"
            fp = _get_machine_fingerprint()
            assert os.environ["HOME"] == "C:\\Users\\testuser"
            assert isinstance(fp, bytes) and len(fp) == 32


class TestSplitJoinKey:
    def test_roundtrip(self):
        key = _generate_master_key()
        parts = _split_key(key)
        assert len(parts) == 3
        assert _join_key(parts) == key

    def test_split_produces_correct_count(self):
        key = _generate_master_key()
        parts = _split_key(key, 4)
        assert len(parts) == 4
        assert _join_key(parts) == key


class TestKeyComponentEncryption:
    def test_roundtrip(self):
        key = _generate_master_key()
        parts = _split_key(key)
        for i, part in enumerate(parts):
            encrypted = _encrypt_key_component(part, i)
            decrypted = _decrypt_key_component(encrypted, i)
            assert decrypted == part

    def test_different_index_different_ciphertext(self):
        key = _generate_master_key()
        parts = _split_key(key)
        enc0 = _encrypt_key_component(parts[0], 0)
        enc1 = _encrypt_key_component(parts[0], 1)
        assert enc0 != enc1


class TestEncryptDecryptValue:
    def test_roundtrip(self):
        master_key = _generate_master_key()
        nonce = _generate_nonce()
        plaintext = "my-secret-password"
        ciphertext = encrypt_value(plaintext, master_key, nonce)
        assert ciphertext != plaintext
        assert decrypt_value(ciphertext, master_key, nonce) == plaintext

    def test_unicode_roundtrip(self):
        master_key = _generate_master_key()
        nonce = _generate_nonce()
        plaintext = "密码测试🔐"
        ciphertext = encrypt_value(plaintext, master_key, nonce)
        assert decrypt_value(ciphertext, master_key, nonce) == plaintext

    def test_wrong_key_fails(self):
        master_key = _generate_master_key()
        wrong_key = _generate_master_key()
        nonce = _generate_nonce()
        ciphertext = encrypt_value("secret", master_key, nonce)
        try:
            decrypt_value(ciphertext, wrong_key, nonce)
            assert False, "Should have raised exception"
        except Exception:
            pass

    def test_wrong_nonce_fails(self):
        master_key = _generate_master_key()
        nonce = _generate_nonce()
        wrong_nonce = _generate_nonce()
        ciphertext = encrypt_value("secret", master_key, nonce)
        try:
            decrypt_value(ciphertext, master_key, wrong_nonce)
            assert False, "Should have raised exception"
        except Exception:
            pass

    def test_empty_string(self):
        master_key = _generate_master_key()
        nonce = _generate_nonce()
        ciphertext = encrypt_value("", master_key, nonce)
        assert decrypt_value(ciphertext, master_key, nonce) == ""

    def test_ciphertext_is_base64(self):
        master_key = _generate_master_key()
        nonce = _generate_nonce()
        ciphertext = encrypt_value("test", master_key, nonce)
        base64.b64decode(ciphertext)


class TestEncryptMasterKey:
    def test_roundtrip_crypter(self):
        master_key = _generate_master_key()
        crypter, crypt_component = encrypt_master_key(master_key)
        recovered = decrypt_master_key_from_crypter(crypter)
        assert recovered == master_key

    def test_roundtrip_component(self):
        master_key = _generate_master_key()
        crypter, crypt_component = encrypt_master_key(master_key)
        recovered = decrypt_master_key_from_component(crypt_component)
        assert recovered == master_key

    def test_crypter_and_component_recover_same_key(self):
        master_key = _generate_master_key()
        crypter, crypt_component = encrypt_master_key(master_key)
        from_crypter = decrypt_master_key_from_crypter(crypter)
        from_component = decrypt_master_key_from_component(crypt_component)
        assert from_crypter == from_component == master_key


class TestCryptJson:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "crypt.json"
            save_crypt_json(path, "test-component-data")
            data = load_crypt_json(path)
            assert data is not None
            assert data["cryptComponent"] == "test-component-data"
            assert "createTime" in data

    def test_load_nonexistent(self):
        result = load_crypt_json(Path("/nonexistent/crypt.json"))
        assert result is None

    def test_load_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.json"
            path.write_text("not valid json {{{", encoding="utf-8")
            result = load_crypt_json(path)
            assert result is None

    def test_generate_crypt_json_path(self):
        config_dir = Path("/tmp/conf")
        result = generate_crypt_json_path(config_dir)
        assert result == config_dir / "crypto.json"


class TestRecoverMasterKey:
    def test_recover_from_crypter(self):
        master_key = _generate_master_key()
        crypter, crypt_component = encrypt_master_key(master_key)

        with tempfile.TemporaryDirectory() as tmpdir:
            crypt_json_path = Path(tmpdir) / "crypt.json"
            save_crypt_json(crypt_json_path, crypt_component)

            recovered = recover_master_key(crypter, crypt_json_path)
            assert recovered == master_key

    def test_recover_from_component_when_crypter_fails(self):
        master_key = _generate_master_key()
        _, crypt_component = encrypt_master_key(master_key)

        with tempfile.TemporaryDirectory() as tmpdir:
            crypt_json_path = Path(tmpdir) / "crypt.json"
            save_crypt_json(crypt_json_path, crypt_component)

            recovered = recover_master_key("invalid-crypter", crypt_json_path)
            assert recovered == master_key

    def test_recover_fails_both(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crypt_json_path = Path(tmpdir) / "crypt.json"
            save_crypt_json(crypt_json_path, "invalid-component")

            recovered = recover_master_key("invalid-crypter", crypt_json_path)
            assert recovered is None

    def test_recover_fails_no_crypt_json(self):
        master_key = _generate_master_key()
        crypter, _ = encrypt_master_key(master_key)

        with tempfile.TemporaryDirectory() as tmpdir:
            crypt_json_path = Path(tmpdir) / "nonexistent.json"
            recovered = recover_master_key("invalid-crypter", crypt_json_path)
            assert recovered is None

    def test_recover_fails_empty_crypt_component(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crypt_json_path = Path(tmpdir) / "crypt.json"
            save_crypt_json(crypt_json_path, "")
            recovered = recover_master_key("invalid-crypter", crypt_json_path)
            assert recovered is None


class TestEndToEnd:
    def test_full_encrypt_decrypt_cycle(self):
        master_key = _generate_master_key()
        nonce = _generate_nonce()

        secret_field = "MyS3cretP@ssw0rd!"
        token = "x-auth-token-abc123"

        enc_secret = encrypt_value(secret_field, master_key, nonce)
        enc_token = encrypt_value(token, master_key, nonce)

        crypter, crypt_component = encrypt_master_key(master_key)
        nonce_b64 = base64.b64encode(nonce).decode("ascii")

        with tempfile.TemporaryDirectory() as tmpdir:
            crypt_json_path = Path(tmpdir) / "crypt.json"
            save_crypt_json(crypt_json_path, crypt_component)

            recovered_key = recover_master_key(crypter, crypt_json_path)
            assert recovered_key == master_key

            recovered_nonce = base64.b64decode(nonce_b64)
            assert decrypt_value(enc_secret, recovered_key, recovered_nonce) == secret_field
            assert decrypt_value(enc_token, recovered_key, recovered_nonce) == token
