#
# Copyright (c) Huawei Technologies CO., Ltd. 2025. All rights reserved.
#

import hmac
import sys
from datetime import datetime

APIC = "apic"
UTF8 = 'utf-8'
DATE_FORMAT = "%Y%m%dT%H%M%SZ"


class SignV11:
    def __init__(self, signer):
        self.signer = signer
        self._credential_scope = ""

    def _set_credential_scope(self, time):
        formatted_date = time.strftime('%Y%m%d')
        self._credential_scope = formatted_date + "/" + self.signer.region_id + "/" + APIC

    def _get_auth_header_value(self, key, signed_headers, signature):
        return "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
            self.signer.algorithm, key, self._credential_scope, ";".join(signed_headers), signature)

    def _get_real_use_secret(self, key, secret):
        return self._hkdf(key, secret, self._credential_scope)

    def _hkdf(self, key, secret, credential_scope, length=32):
        salt = bytearray(key, UTF8)
        ikm = bytearray(secret, UTF8)
        info = bytearray(credential_scope, UTF8)
        hash_func = self.signer.hash_func

        # 提取阶段 (HKDF-Extract)
        prk = hmac.new(salt, ikm, hash_func).digest()
        # 扩展阶段 (HKDF-Expand)
        okm = b""
        t = b""
        for i in range(1, (length + 32) // 32 + 1):
            new_info = t + info + bytes([i])
            t = hmac.new(prk, new_info, hash_func).digest()
            okm += t

        return okm[:length].hex()

    def generate_auth(self, canonical_request, t, signed_headers):
        s = self.signer
        if s is None:
            raise ValueError("he signer is None")
        string_to_sign_str = self._get_string_to_sign(canonical_request, t)
        real_use_secret = self._get_real_use_secret(s.Key, s.Secret)
        signature = s.sign_string_to_sign(real_use_secret, string_to_sign_str)
        auth_value = self._get_auth_header_value(s.Key, signed_headers, signature)
        return auth_value

    if sys.version_info.major < 3:
        def _get_string_to_sign(self, request, time):
            hashed_canonical_request = self.signer.hex_encode_hash(request)
            self._set_credential_scope(time)
            return "%s\n%s\n%s\n%s" % (self.signer.algorithm, datetime.strftime(time, DATE_FORMAT),
                                       self._credential_scope, hashed_canonical_request)

    else:
        def _get_string_to_sign(self, request, time):
            hashed_canonical_request = self.signer.hex_encode_hash(request.encode(UTF8))
            self._set_credential_scope(time)
            return "%s\n%s\n%s\n%s" % (self.signer.algorithm, datetime.strftime(time, DATE_FORMAT),
                                       self._credential_scope, hashed_canonical_request)
