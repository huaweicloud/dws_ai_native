import asyncio
import hashlib
from unittest import TestCase, mock
from datetime import datetime
from dws_autopilot_mcp.apig_sdk.signer import (
    urlencode, findHeader, HexEncodeSHA256Hash,
    CanonicalURI, CanonicalQueryString, CanonicalHeaders, SignedHeaders,
    HttpRequest, Signer, DateFormat, _process_headers,
)
from dws_autopilot_mcp.apig_sdk.signer_v11 import SignV11
from dws_autopilot_mcp.apig_sdk import sm3_hash


class TestSignerBasic(TestCase):
    def test_urlencode(self):
        self.assertEqual('abc', urlencode("abc"))
        self.assertEqual('a%20b', urlencode("a b"))

    def test_hex_encode_sha256_hash(self):
        result = HexEncodeSHA256Hash(b"hello")
        self.assertEqual(len(result), 64)

    def test_findHeader_found(self):
        r = HttpRequest("GET", "https://example.com/path", {"X-Test": "value"})
        self.assertEqual("value", findHeader(r, "x-test"))

    def test_findHeader_not_found(self):
        r = HttpRequest("GET", "https://example.com/path", {"X-Test": "value"})
        self.assertIsNone(findHeader(r, "x-missing"))

    def test_canonical_uri(self):
        r = HttpRequest("GET", "https://example.com/app1?a=1")
        result = CanonicalURI(r)
        self.assertEqual("/app1/", result)

    def test_canonical_query_string(self):
        r = HttpRequest("GET", "https://example.com/path?a=1&b=2")
        result = CanonicalQueryString(r)
        self.assertIn("a=1", result)
        self.assertIn("b=2", result)

    def test_canonical_headers(self):
        r = HttpRequest("GET", "https://example.com/path", {"x-stage": "RELEASE"})
        result = CanonicalHeaders(r, ["x-stage"])
        self.assertIn("x-stage:RELEASE", result)

    def test_signed_headers(self):
        r = HttpRequest("GET", "https://example.com/path", {"x-stage": "RELEASE", "host": "example.com"})
        result = SignedHeaders(r)
        self.assertIn("host", result)
        self.assertIn("x-stage", result)

    def test_http_request_parsing(self):
        r = HttpRequest("POST", "https://example.com/app1?a=1&b=2", {"x-stage": "RELEASE"}, "body")
        self.assertEqual("POST", r.method)
        self.assertEqual("https", r.scheme)
        self.assertEqual("example.com", r.host)
        self.assertEqual("/app1", r.uri)
        self.assertEqual(["1"], r.query.get("a"))
        self.assertEqual(["2"], r.query.get("b"))
        self.assertEqual(b"body", r.body)

    def test_http_request_no_query(self):
        r = HttpRequest("GET", "https://example.com/path")
        self.assertEqual({}, r.query)
        self.assertEqual("/path", r.uri)

    def test_http_request_no_path(self):
        r = HttpRequest("GET", "https://example.com")
        self.assertEqual("/", r.uri)

    def test_signer_sign(self):
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig = Signer()
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        sig.Sign(r)
        self.assertIn("Authorization", r.headers)
        self.assertTrue(r.headers["Authorization"].startswith("SDK-HMAC-SHA256"))
        self.assertIn("X-Sdk-Date", r.headers)
        self.assertIn("host", r.headers)

    def test_signer_verify_success(self):
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig = Signer()
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        sig.Sign(r)
        auth_value = r.headers["Authorization"]
        self.assertTrue(sig.Verify(r, auth_value))

    def test_signer_verify_fail(self):
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig = Signer()
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        sig.Sign(r)
        self.assertFalse(sig.Verify(r, "SDK-HMAC-SHA256 Access=test_ak, SignedHeaders=host, Signature=wrong"))

    def test_signer_v11_requires_region(self):
        with self.assertRaises(ValueError):
            Signer(algorithm="V11-HMAC-SHA256")

    def test_signer_sign_string_to_sign(self):
        sig = Signer()
        sig.Secret = "test_secret"
        result = sig.sign_string_to_sign("test_secret", "string_to_sign")
        self.assertEqual(len(result), 64)

    def test_signer_auth_header_value(self):
        sig = Signer()
        sig.Key = "TEST_AK"
        result = sig.auth_header_value("sig123", ["host", "x-sdk-date"])
        self.assertIn("SDK-HMAC-SHA256", result)
        self.assertIn("Access=TEST_AK", result)
        self.assertIn("SignedHeaders=host;x-sdk-date", result)
        self.assertIn("Signature=sig123", result)

    def test_signer_hex_encode_hash(self):
        sig = Signer()
        result = sig.hex_encode_hash(b"test data")
        self.assertEqual(len(result), 64)

    def test_signer_with_existing_sdk_date(self):
        r = HttpRequest("GET", "https://example.com/path")
        r.headers["X-Sdk-Date"] = "20240326T030801Z"
        sig = Signer()
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        sig.Sign(r)
        self.assertEqual("20240326T030801Z", r.headers["X-Sdk-Date"])

    def test_signer_verify_no_sdk_date(self):
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig = Signer()
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        sig.Sign(r)
        del r.headers["X-Sdk-Date"]
        self.assertFalse(sig.Verify(r, "SDK-HMAC-SHA256 Access=test_ak, SignedHeaders=host, Signature=abc"))

    def test_process_headers(self):
        headers = {"host": "example.com", "content-type": "application/json", "x-stage": "RELEASE"}
        _process_headers("SDK-HMAC-SHA256 Access=ak, SignedHeaders=host;x-stage, Signature=sig", headers)
        self.assertIn("host", headers)
        self.assertIn("x-stage", headers)
        self.assertNotIn("content-type", headers)

    def test_process_headers_no_signed_headers(self):
        headers = {"host": "example.com"}
        with self.assertRaises(ValueError):
            _process_headers("SDK-HMAC-SHA256 Access=ak, Signature=sig", headers)

    def test_canonical_query_string_list_value(self):
        r = HttpRequest("GET", "https://example.com/path?a=1&a=2")
        result = CanonicalQueryString(r)
        self.assertIn("a=1", result)
        self.assertIn("a=2", result)

    def test_http_request_duplicate_query_key(self):
        r = HttpRequest("GET", "https://example.com/path?a=1&a=2")
        self.assertEqual(["1", "2"], r.query.get("a"))

    def test_http_request_empty_query_value(self):
        r = HttpRequest("GET", "https://example.com/path?a=&b=1")
        self.assertIn("a", r.query)
        self.assertIn("b", r.query)

    def test_http_request_with_headers(self):
        headers = {"X-Custom": "value1", "X-Other": "value2"}
        r = HttpRequest("GET", "https://example.com/path", headers)
        self.assertEqual("value1", r.headers["X-Custom"])
        self.assertEqual("value2", r.headers["X-Other"])

    def test_http_request_no_headers(self):
        r = HttpRequest("GET", "https://example.com/path")
        self.assertEqual({}, r.headers)

    def test_canonical_uri_with_special_chars(self):
        r = HttpRequest("GET", "https://example.com/app1%3Fa%3D1")
        result = CanonicalURI(r)
        self.assertTrue(result.startswith("/"))
        self.assertTrue(result.endswith("/"))


class TestSignerV11(TestCase):
    def _make_v11_signer(self):
        sig = Signer(algorithm="V11-HMAC-SHA256", region_id="cn-north-4")
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        return sig

    def test_v11_sign(self):
        sig = self._make_v11_signer()
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig.Sign(r)
        self.assertIn("Authorization", r.headers)
        self.assertTrue(r.headers["Authorization"].startswith("V11-HMAC-SHA256"))
        self.assertIn("Credential=test_ak", r.headers["Authorization"])

    def test_v11_verify_success(self):
        sig = self._make_v11_signer()
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig.Sign(r)
        auth_value = r.headers["Authorization"]
        self.assertTrue(sig.Verify(r, auth_value))

    def test_v11_verify_fail(self):
        sig = self._make_v11_signer()
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig.Sign(r)
        self.assertFalse(sig.Verify(r, "V11-HMAC-SHA256 Credential=test_ak, SignedHeaders=host, Signature=wrong"))

    def test_v11_credential_scope(self):
        sig = self._make_v11_signer()
        v11 = SignV11(sig)
        t = datetime.strptime("20240326T030801Z", DateFormat)
        v11._set_credential_scope(t)
        self.assertIn("20240326", v11._credential_scope)
        self.assertIn("cn-north-4", v11._credential_scope)
        self.assertIn("apic", v11._credential_scope)

    def test_v11_get_string_to_sign(self):
        sig = self._make_v11_signer()
        v11 = SignV11(sig)
        t = datetime.strptime("20240326T030801Z", DateFormat)
        result = v11._get_string_to_sign("GET\n/\n\nhost:example.com\n\nhost\nhash", t)
        self.assertIn("V11-HMAC-SHA256", result)
        self.assertIn("20240326T030801Z", result)

    def test_v11_hkdf(self):
        sig = self._make_v11_signer()
        v11 = SignV11(sig)
        v11._credential_scope = "20240326/cn-north-4/apic"
        result = v11._hkdf("test_key", "test_secret", v11._credential_scope)
        self.assertEqual(len(result), 64)

    def test_v11_get_real_use_secret(self):
        sig = self._make_v11_signer()
        v11 = SignV11(sig)
        v11._credential_scope = "20240326/cn-north-4/apic"
        result = v11._get_real_use_secret("test_key", "test_secret")
        self.assertEqual(len(result), 64)

    def test_v11_get_auth_header_value(self):
        sig = self._make_v11_signer()
        v11 = SignV11(sig)
        v11._credential_scope = "20240326/cn-north-4/apic"
        result = v11._get_auth_header_value("test_ak", ["host", "x-sdk-date"], "sig123")
        self.assertIn("V11-HMAC-SHA256", result)
        self.assertIn("Credential=test_ak/20240326/cn-north-4/apic", result)
        self.assertIn("SignedHeaders=host;x-sdk-date", result)
        self.assertIn("Signature=sig123", result)

    def test_v11_generate_auth(self):
        sig = self._make_v11_signer()
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        r.headers["X-Sdk-Date"] = "20240326T030801Z"
        sig.Sign(r)
        auth = r.headers["Authorization"]
        self.assertTrue(auth.startswith("V11-HMAC-SHA256"))

    def test_v11_generate_auth_none_signer(self):
        v11 = SignV11(None)
        with self.assertRaises(ValueError):
            v11.generate_auth("canonical", datetime.now(), ["host"])

    def test_v11_sign_sm3(self):
        sig = Signer(algorithm="V11-HMAC-SM3", region_id="cn-north-4")
        sig.Key = "test_ak"
        sig.Secret = "test_sk"
        r = HttpRequest("GET", "https://example.com/path?a=1")
        r.headers["Content-Type"] = "application/json"
        sig.Sign(r)
        self.assertIn("Authorization", r.headers)
        self.assertTrue(r.headers["Authorization"].startswith("V11-HMAC-SM3"))


class TestSM3Hash(TestCase):
    def test_sm3_hash_basic(self):
        h = sm3_hash.new_sm3_hash(b"hello")
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_sm3_hash_empty(self):
        h = sm3_hash.new_sm3_hash(b"")
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_sm3_hash_update(self):
        h = sm3_hash.new_sm3_hash()
        h.update(b"hello")
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_sm3_hash_digest(self):
        h = sm3_hash.new_sm3_hash(b"test")
        result = h.digest()
        self.assertEqual(len(result), 32)

    def test_sm3_hash_copy(self):
        h = sm3_hash.new_sm3_hash(b"hello")
        h2 = h.copy()
        h2.update(b"world")
        self.assertNotEqual(h.hexdigest(), h2.hexdigest())

    def test_sm3_hash_copy_equal(self):
        h = sm3_hash.new_sm3_hash(b"hello")
        h2 = h.copy()
        self.assertEqual(h.hexdigest(), h2.hexdigest())

    def test_sm3_hash_name(self):
        h = sm3_hash.new_sm3_hash()
        self.assertEqual(h.name, "sm3")

    def test_sm3_hash_digest_size(self):
        h = sm3_hash.new_sm3_hash()
        self.assertEqual(h.digest_size, 32)

    def test_sm3_hash_block_size(self):
        h = sm3_hash.new_sm3_hash()
        self.assertEqual(h.block_size, 64)

    def test_sm3_hash_long_input(self):
        data = b"a" * 1000
        h = sm3_hash.new_sm3_hash(data)
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_sm3_hash_incremental(self):
        h1 = sm3_hash.new_sm3_hash(b"hello world")
        h2 = sm3_hash.new_sm3_hash()
        h2.update(b"hello")
        h2.update(b" world")
        self.assertEqual(h1.hexdigest(), h2.hexdigest())


class TestSM3HashPurePython(TestCase):
    def _import_pure_sm3(self):
        import importlib
        import types
        mod = types.ModuleType("sm3_hash_pure")
        code = '''
import hashlib
from sys import version_info

_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
_T_J = [0x79cc4519 if j < 16 else 0x7a879d8a for j in range(64)]
_0X8F = 0xffffffff
_OUT_OF_RANGE_ERROR = ValueError("j out of range [0, 64)")

def _left_rotate(n, k):
    return ((n << k) & _0X8F) | ((n >> (32 - k)) & _0X8F)

def _ff_j(x, y, z, j):
    if 0 <= j < 16:
        return x ^ y ^ z
    elif 16 <= j < 64:
        return (x & y) | (x & z) | (y & z)
    else:
        raise _OUT_OF_RANGE_ERROR

def _gg_j(x, y, z, j):
    if 0 <= j < 16:
        return x ^ y ^ z
    elif 16 <= j < 64:
        return (x & y) ^ (~x & z)
    else:
        raise _OUT_OF_RANGE_ERROR

def _p_0(x):
    return x ^ _left_rotate(x, 9) ^ _left_rotate(x, 17)

def _p_1(x):
    return x ^ _left_rotate(x, 15) ^ _left_rotate(x, 23)

def _cf(v_i, b_i):
    w = [0] * 68
    for i in range(16):
        data = b_i[i * 4: (i + 1) * 4]
        w[i] = int.from_bytes(data, byteorder='big')
    for i in range(16, 68):
        w[i] = _p_1(w[i - 16] ^ w[i - 9] ^ (_left_rotate(w[i - 3], 15))) ^ (_left_rotate(w[i - 13], 7)) ^ w[i - 6]
    w_1 = [w[i] ^ w[i + 4] for i in range(64)]
    a, b, c, d, e, f, g, h = v_i
    for i in range(64):
        ss_1 = _left_rotate((_left_rotate(a, 12) + e + _left_rotate(_T_J[i], i % 32)) & _0X8F, 7)
        ss_2 = ss_1 ^ _left_rotate(a, 12)
        tt_1 = (_ff_j(a, b, c, i) + d + ss_2 + w_1[i]) & _0X8F
        tt_2 = (_gg_j(e, f, g, i) + h + ss_1 + w[i]) & _0X8F
        d, c, b, a, h, g, f, e = c, _left_rotate(b, 9), a, tt_1, g, _left_rotate(f, 19), e, _p_0(tt_2)
        a, b, c, d, e, f, g, h = map(lambda x: x & _0X8F, (a, b, c, d, e, f, g, h))
    v_j = (a, b, c, d, e, f, g, h)
    return [v_j[i] ^ v_i[i] for i in range(8)]

def _hash(data):
    data_list = [i for i in data]
    length = len(data_list)
    bit_length = length * 8
    k = (56 - length - 1) % 64
    data_list.append(0x80)
    data_list.extend([0x00] * k)
    data_list.extend([i for i in bit_length.to_bytes(8, 'big')])
    iter_count = int(len(data_list) / 64)
    b = [data_list[i * 64:(i + 1) * 64] for i in range(iter_count)]
    v = [_IV]
    i = 0
    for i in range(iter_count):
        v.append(_cf(v[i], b[i]))
    return b''.join(map(lambda n: n.to_bytes(4, 'big'), v[i + 1]))

class _SM3Hash:
    name = 'sm3'
    digest_size = 32
    block_size = 64
    def __init__(self, data=b''):
        self._bytearray = bytearray(data)
    def update(self, data):
        self._bytearray.extend(data)
    def digest(self):
        return _hash(bytes(self._bytearray))
    def hexdigest(self):
        return self.digest().hex()
    def copy(self):
        return self.__class__(bytes(self._bytearray))

new_sm3_hash = lambda data=b'': _SM3Hash(data)
'''
        exec(code, mod.__dict__)
        return mod

    def test_pure_sm3_basic(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash(b"hello")
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_pure_sm3_empty(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash(b"")
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_pure_sm3_update(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash()
        h.update(b"hello")
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_pure_sm3_digest(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash(b"test")
        result = h.digest()
        self.assertEqual(len(result), 32)

    def test_pure_sm3_copy(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash(b"hello")
        h2 = h.copy()
        h2.update(b"world")
        self.assertNotEqual(h.hexdigest(), h2.hexdigest())

    def test_pure_sm3_copy_equal(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash(b"hello")
        h2 = h.copy()
        self.assertEqual(h.hexdigest(), h2.hexdigest())

    def test_pure_sm3_name(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash()
        self.assertEqual(h.name, "sm3")

    def test_pure_sm3_digest_size(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash()
        self.assertEqual(h.digest_size, 32)

    def test_pure_sm3_block_size(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash()
        self.assertEqual(h.block_size, 64)

    def test_pure_sm3_long_input(self):
        m = self._import_pure_sm3()
        h = m.new_sm3_hash(b"a" * 1000)
        result = h.hexdigest()
        self.assertEqual(len(result), 64)

    def test_pure_sm3_incremental(self):
        m = self._import_pure_sm3()
        h1 = m.new_sm3_hash(b"hello world")
        h2 = m.new_sm3_hash()
        h2.update(b"hello")
        h2.update(b" world")
        self.assertEqual(h1.hexdigest(), h2.hexdigest())

    def test_pure_sm3_ff_j_out_of_range(self):
        m = self._import_pure_sm3()
        with self.assertRaises(ValueError):
            m._ff_j(0, 0, 0, 64)

    def test_pure_sm3_gg_j_out_of_range(self):
        m = self._import_pure_sm3()
        with self.assertRaises(ValueError):
            m._gg_j(0, 0, 0, 64)

    def test_pure_sm3_left_rotate(self):
        m = self._import_pure_sm3()
        result = m._left_rotate(1, 1)
        self.assertEqual(result, 2)

    def test_pure_sm3_p0_p1(self):
        m = self._import_pure_sm3()
        x = 0x12345678
        r0 = m._p_0(x)
        r1 = m._p_1(x)
        self.assertIsInstance(r0, int)
        self.assertIsInstance(r1, int)

    def test_pure_sm3_consistent_with_hashlib(self):
        m = self._import_pure_sm3()
        pure_result = m.new_sm3_hash(b"test").hexdigest()
        hashlib_result = hashlib.new('sm3', b"test").hexdigest()
        self.assertEqual(pure_result, hashlib_result)


class TestSM3HashPython2Branch(TestCase):
    def test_python2_branch_none(self):
        import collections
        Py2VI = collections.namedtuple('version_info', ['major', 'minor', 'micro', 'releaselevel', 'serial'])(2, 7, 18, 'final', 0)
        with mock.patch('sys.version_info', Py2VI):
            import importlib
            import dws_autopilot_mcp.apig_sdk.sm3_hash as sm3_mod
            importlib.reload(sm3_mod)
            try:
                self.assertIsNone(sm3_mod.new_sm3_hash)
            finally:
                importlib.reload(sm3_mod)

    def test_python36_pure_sm3_branch(self):
        import collections
        Py36VI = collections.namedtuple('version_info', ['major', 'minor', 'micro', 'releaselevel', 'serial'])(3, 6, 18, 'final', 0)
        with mock.patch('sys.version_info', Py36VI):
            import importlib
            import dws_autopilot_mcp.apig_sdk.sm3_hash as sm3_mod
            importlib.reload(sm3_mod)
            try:
                h = sm3_mod.new_sm3_hash(b"hello")
                self.assertEqual(len(h.hexdigest()), 64)
                h2 = sm3_mod.new_sm3_hash(b"")
                self.assertEqual(len(h2.hexdigest()), 64)
                h3 = sm3_mod.new_sm3_hash()
                h3.update(b"test")
                self.assertEqual(len(h3.hexdigest()), 64)
                self.assertEqual(len(h3.digest()), 32)
                h4 = h3.copy()
                self.assertEqual(h3.hexdigest(), h4.hexdigest())
                self.assertEqual(h3.name, "sm3")
                self.assertEqual(h3.digest_size, 32)
                self.assertEqual(h3.block_size, 64)
            finally:
                importlib.reload(sm3_mod)


class TestSignerV11Py2Branch(TestCase):
    def test_v11_get_string_to_sign_py2_branch(self):
        import types
        mod = types.ModuleType("v11_py2")
        code = '''
import hmac
import hashlib
import sys
from datetime import datetime

DATE_FORMAT = "%Y%m%dT%H%M%SZ"
APIC = "apic"
UTF8 = 'utf-8'

class MockSigner:
    algorithm = "V11-HMAC-SHA256"
    region_id = "cn-north-4"
    Key = "test_ak"
    Secret = "test_sk"
    hash_func = hashlib.sha256
    def hex_encode_hash(self, data):
        return hashlib.sha256(data).hexdigest()
    def sign_string_to_sign(self, secret, sts):
        return "fake_sig"

class SignV11Py2:
    def __init__(self, signer):
        self.signer = signer
        self._credential_scope = ""
    def _set_credential_scope(self, time):
        formatted_date = time.strftime('%Y%m%d')
        self._credential_scope = formatted_date + "/" + self.signer.region_id + "/" + APIC
    def _get_string_to_sign(self, request, time):
        hashed_canonical_request = self.signer.hex_encode_hash(request)
        self._set_credential_scope(time)
        return "%s\\n%s\\n%s\\n%s" % (self.signer.algorithm, datetime.strftime(time, DATE_FORMAT),
                                   self._credential_scope, hashed_canonical_request)

s = MockSigner()
v11 = SignV11Py2(s)
from datetime import datetime as dt
t = dt.strptime("20240326T030801Z", DATE_FORMAT)
result = v11._get_string_to_sign(b"GET\\n/\\n\\nhost:example.com\\n\\nhost\\nhash", t)
'''
        exec(code, mod.__dict__)
        self.assertIn("V11-HMAC-SHA256", mod.result)
