#
# Copyright (c) Huawei Technologies CO., Ltd. 2022-2025. All rights reserved.
#
import copy
import re
import sys
import hashlib
import hmac
import binascii
from . import sm3_hash
from .signer_v11 import SignV11
from datetime import datetime

if sys.version_info.major < 3:
    from urllib import quote, unquote
else:
    from urllib.parse import quote, unquote

DateFormat = "%Y%m%dT%H%M%SZ"
HXDate = "X-Sdk-Date"
HHost = "host"
HAuthorization = "Authorization"
HSdkContent = "x-sdk-content-"
UTF8 = "utf-8"
V11 = "V11"
SHA256 = "SHA256"
SDK_HMAC_SHA256 = "SDK-HMAC-SHA256"
SDK_HMAC_SM3 = "SDK-HMAC-SM3"
V11_HMAC_SHA256 = "V11-HMAC-SHA256"
V11_HMAC_SM3 = "V11-HMAC-SM3"
alg_set = {"SDK-HMAC-SHA256", "SDK-HMAC-SM3", "V11-HMAC-SHA256", "V11-HMAC-SM3"}


def urlencode(str):
    return quote(str, safe='~')


def findHeader(req, h):
    for header in req.headers:
        if header.lower() == h.lower():
            return req.headers[header]
    return None


# HexEncodeSHA256Hash returns hexcode of sha256
def HexEncodeSHA256Hash(d):
    sha = hashlib.sha256()
    sha.update(d)
    return sha.hexdigest()


def CanonicalURI(req):
    patterns = unquote(req.uri).split('/')
    uri = []
    for value in patterns:
        uri.append(urlencode(value))
    url_path = "/".join(uri)
    if url_path[-1] != '/':
        url_path = url_path + "/"  # always end with /
    # r.uri = urlpath
    return url_path


def CanonicalQueryString(req):
    keys = []
    for key in req.query:
        keys.append(key)
    keys.sort()
    arr = []
    for key in keys:
        ke = urlencode(key)
        value = req.query[key]
        if type(value) is list:
            value.sort()
            for v in value:
                kv = ke + "=" + urlencode(str(v))
                arr.append(kv)
        else:
            kv = ke + "=" + urlencode(str(value))
            arr.append(kv)
    return '&'.join(arr)


def CanonicalHeaders(req, sHeaders):
    arr = []
    _headers = {}
    for k in req.headers:
        keyEncoded = k.lower()
        value = req.headers[k]
        valueEncoded = value.strip()
        _headers[keyEncoded] = valueEncoded
        if sys.version_info.major == 3:
            req.headers[k] = valueEncoded.encode(UTF8).decode('iso-8859-1')
    for k in sHeaders:
        arr.append(k + ":" + _headers[k])
    return '\n'.join(arr) + "\n"


def SignedHeaders(req):
    arr = []
    for k in req.headers:
        arr.append(k.lower())
    arr.sort()
    return arr


def _process_headers(signature_header, request_headers):
    match = re.search(r"SignedHeaders=([^, ]+)", signature_header)
    if not match:
        raise ValueError("SignedHeaders 未找到")
    signed_headers_str = match.group(1)
    signed_headers = [h.strip().lower() for h in signed_headers_str.split(";") if h.strip()]

    for key in list(request_headers.keys()):
        if key.lower() not in signed_headers:
            request_headers.pop(key, None)


class Signer:
    def __init__(self, algorithm=SDK_HMAC_SHA256, region_id=""):
        self.Key = ""
        self.Secret = ""
        self.algorithm = algorithm.upper()
        if self.algorithm.startswith(V11) and len(region_id) == 0:
            raise ValueError("region id is required when you use V11 encryption algorithm")
        self.region_id = region_id
        if self.algorithm.endswith(SHA256):
            self.hash_func = hashlib.sha256
        else:
            self.hash_func = sm3_hash.new_sm3_hash

    def Verify(self, req, authorization):
        if sys.version_info.major == 3 and isinstance(req.body, str):
            req.body = req.body.encode(UTF8)
        header_time = findHeader(req, HXDate)
        if header_time is None:
            return False
        else:
            datetime.strptime(header_time, DateFormat)

        r_verify = copy.deepcopy(req)
        r_verify.headers.pop(HAuthorization, None)
        _process_headers(authorization, r_verify.headers)
        auth_value = self._get_auth_value(r_verify)
        return authorization == auth_value

    # SignRequest set Authorization header
    def Sign(self, req):
        if sys.version_info.major == 3 and isinstance(req.body, str):
            req.body = req.body.encode(UTF8)
        auth_value = self._get_auth_value(req)
        req.headers[HAuthorization] = auth_value

    # Build a CanonicalRequest from a regular request string
    #
    # CanonicalRequest =
    #  HTTPRequestMethod + '\n' +
    #  CanonicalURI + '\n' +
    #  CanonicalQueryString + '\n' +
    #  CanonicalHeaders + '\n' +
    #  SignedHeaders + '\n' +
    #  HexEncode(Hash(RequestPayload))
    def _canonical_request(self, req, signed_headers):
        canonical_headers = CanonicalHeaders(req, signed_headers)
        hencode = findHeader(req, self._get_not_sign_body_header_key())
        if hencode is None:
            hencode = self.hex_encode_hash(req.body)
        return "%s\n%s\n%s\n%s\n%s\n%s" % (req.method.upper(), CanonicalURI(req), CanonicalQueryString(req),
                                           canonical_headers, ";".join(signed_headers), hencode)

    def _get_not_sign_body_header_key(self):
        temp_arr = self.algorithm.split("-")
        real_use_alg = temp_arr[-1].lower()
        return HSdkContent + real_use_alg

    def _get_auth_value(self, req):
        header_time = findHeader(req, HXDate)
        if header_time is None:
            time = datetime.utcnow()
            req.headers[HXDate] = datetime.strftime(time, DateFormat)
        else:
            time = datetime.strptime(header_time, DateFormat)
        have_host = False
        for key in req.headers:
            if key.lower() == HHost:
                have_host = True
                break
        if not have_host:
            req.headers[HHost] = req.host
        signed_headers = SignedHeaders(req)
        canonical_request = self._canonical_request(req, signed_headers)
        if self.algorithm.startswith(V11):
            sign_v11 = SignV11(self)
            auth_value = sign_v11.generate_auth(canonical_request, time, signed_headers)
        else:
            string_to_sign = self._get_string_to_sign(canonical_request, time)
            signature = self.sign_string_to_sign(self.Secret, string_to_sign)
            auth_value = self.auth_header_value(signature, signed_headers)
        return auth_value

    # Create the HWS Signature.
    def sign_string_to_sign(self, secret_key, string_to_sign):
        sign_hmac = self._new_hmac(secret_key, string_to_sign)
        return binascii.hexlify(sign_hmac).decode()

    # Get the finalized value for the "Authorization" header.  The signature
    # parameter is the output from SignStringToSign
    def auth_header_value(self, sig, signed_headers):
        return "%s Access=%s, SignedHeaders=%s, Signature=%s" % (
            self.algorithm, self.Key, ";".join(signed_headers), sig)

    def hex_encode_hash(self, data):
        # type: (bytes) -> str
        _hash = self.hash_func(data)
        return _hash.hexdigest()

    if sys.version_info.major < 3:
        def _new_hmac(self, byte, msg):
            return hmac.new(byte, msg, digestmod=self.hash_func).digest()

        def _get_string_to_sign(self, request, time):
            b = self.hex_encode_hash(request)
            return "%s\n%s\n%s" % (self.algorithm, datetime.strftime(time, DateFormat), b)

    else:
        def _new_hmac(self, byte, msg):
            return hmac.new(byte.encode(UTF8), msg.encode(UTF8), digestmod=self.hash_func).digest()

        def _get_string_to_sign(self, request, time):
            b = self.hex_encode_hash(request.encode(UTF8))
            return "%s\n%s\n%s" % (self.algorithm, datetime.strftime(time, DateFormat), b)


# HWS API Gateway Signature
class HttpRequest:
    def __init__(self, m="", u="", h=None, b=""):
        self.method = m
        sp = u.split("://", 1)
        s = 'http'
        if len(sp) > 1:
            s = sp[0]
            u = sp[1]
        q = {}
        sp = u.split('?', 1)
        u = sp[0]
        if len(sp) > 1:
            for kv in sp[1].split("&"):
                sp = kv.split("=", 1)
                k = sp[0]
                v = ""
                if len(sp) > 1:
                    v = sp[1]
                if k != '':
                    k = unquote(k)
                    v = unquote(v)
                    if k in q:
                        q[k].append(v)
                    else:
                        q[k] = [v]
        sp = u.split('/', 1)
        host = sp[0]
        if len(sp) > 1:
            u = '/' + sp[1]
        else:
            u = '/'

        self.scheme = s
        self.host = host
        self.uri = u
        self.query = q
        if h is None:
            self.headers = {}
        else:
            self.headers = copy.deepcopy(h)
        if sys.version_info.major < 3:
            self.body = b
        else:
            self.body = b.encode("utf-8")
