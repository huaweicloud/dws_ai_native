import os
import base64
import hashlib
import json
import time
import logging
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("dws_autopilot_mcp")

_NONCE_LEN = 12
_KEY_LEN = 32
_COMPONENT_SEP = ";"
_COMPONENT_COUNT = 3


def _get_machine_fingerprint() -> bytes:
    # On Windows, HOME may not be set in all contexts (e.g. CodeAgent child processes).
    # Normalize: if HOME is missing, derive it from USERPROFILE or HOMEDRIVE+HOMEPATH.
    if not os.environ.get("HOME"):
        userprofile = os.environ.get("USERPROFILE", "")
        if userprofile:
            os.environ["HOME"] = userprofile
        else:
            home_drive = os.environ.get("HOMEDRIVE", "")
            home_path = os.environ.get("HOMEPATH", "")
            if home_drive and home_path:
                os.environ["HOME"] = home_drive + home_path
    parts = []
    for env_var in ("USERNAME", "COMPUTERNAME", "USERDOMAIN", "HOME", "USER"):
        val = os.environ.get(env_var, "")
        if val:
            parts.append(val)
    if not parts:
        parts.append("dws-mcp-default-fingerprint")
    return hashlib.sha256("|".join(parts).encode()).digest()


def _derive_local_key(salt: bytes) -> bytes:
    fingerprint = _get_machine_fingerprint()
    return hashlib.pbkdf2_hmac("sha256", fingerprint, salt, 100000, dklen=_KEY_LEN)


def _generate_master_key() -> bytes:
    return os.urandom(_KEY_LEN)


def _generate_nonce() -> bytes:
    return os.urandom(_NONCE_LEN)


def _split_key(key: bytes, n: int = _COMPONENT_COUNT) -> list[bytes]:
    step = len(key) // n
    parts = []
    for i in range(n - 1):
        parts.append(key[i * step : (i + 1) * step])
    parts.append(key[(n - 1) * step :])
    return parts


def _join_key(parts: list[bytes]) -> bytes:
    return b"".join(parts)


def _encrypt_key_component(part: bytes, index: int) -> bytes:
    salt = _get_machine_fingerprint() + str(index).encode()
    local_key = _derive_local_key(salt)
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(local_key)
    ct = aesgcm.encrypt(nonce, part, None)
    return nonce + ct


def _decrypt_key_component(encrypted: bytes, index: int) -> bytes:
    salt = _get_machine_fingerprint() + str(index).encode()
    local_key = _derive_local_key(salt)
    nonce = encrypted[:_NONCE_LEN]
    ct = encrypted[_NONCE_LEN:]
    aesgcm = AESGCM(local_key)
    return aesgcm.decrypt(nonce, ct, None)


def encrypt_value(plaintext: str, master_key: bytes, nonce: bytes) -> str:
    aesgcm = AESGCM(master_key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(ct).decode("ascii")


def decrypt_value(ciphertext: str, master_key: bytes, nonce: bytes) -> str:
    aesgcm = AESGCM(master_key)
    ct = base64.b64decode(ciphertext)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def encrypt_master_key(master_key: bytes) -> tuple[str, str]:
    salt = _get_machine_fingerprint()
    local_key = _derive_local_key(salt)
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(local_key)
    ct = aesgcm.encrypt(nonce, master_key, None)
    crypter = base64.b64encode(nonce + ct).decode("ascii")

    parts = _split_key(master_key)
    encrypted_parts = [_encrypt_key_component(p, i) for i, p in enumerate(parts)]
    encoded_parts = [base64.b64encode(ep).decode("ascii") for ep in encrypted_parts]
    crypt_component = _COMPONENT_SEP.join(encoded_parts)

    return crypter, crypt_component


def decrypt_master_key_from_crypter(crypter: str) -> bytes | None:
    try:
        raw = base64.b64decode(crypter)
        nonce = raw[:_NONCE_LEN]
        ct = raw[_NONCE_LEN:]
        salt = _get_machine_fingerprint()
        local_key = _derive_local_key(salt)
        aesgcm = AESGCM(local_key)
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        logger.warning("Failed to decrypt master key from crypter: %s", e)
        return None


def decrypt_master_key_from_component(crypt_component: str) -> bytes | None:
    try:
        encoded_parts = crypt_component.split(_COMPONENT_SEP)
        if len(encoded_parts) != _COMPONENT_COUNT:
            logger.warning("Invalid crypt component count: %d", len(encoded_parts))
            return None
        parts = []
        for i, ep in enumerate(encoded_parts):
            encrypted = base64.b64decode(ep)
            part = _decrypt_key_component(encrypted, i)
            parts.append(part)
        return _join_key(parts)
    except Exception as e:
        logger.warning("Failed to decrypt master key from component: %s", e)
        return None


def generate_crypt_json_path(config_dir: Path) -> Path:
    return config_dir / "crypto.json"


def load_crypt_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to load crypto.json: %s", e)
        return None


def save_crypt_json(path: Path, crypt_component: str) -> None:
    data = {
        "createTime": int(time.time()),
        "cryptComponent": crypt_component,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent="\t")


def recover_master_key(crypter: str, crypt_json_path: Path) -> bytes | None:
    master_key = decrypt_master_key_from_crypter(crypter)
    if master_key is not None:
        return master_key

    crypt_data = load_crypt_json(crypt_json_path)
    if crypt_data is None:
        logger.warning("crypto.json not found and crypter decryption failed")
        return None

    crypt_component = crypt_data.get("cryptComponent", "")
    if not crypt_component:
        logger.warning("cryptComponent is empty in crypto.json")
        return None

    return decrypt_master_key_from_component(crypt_component)
