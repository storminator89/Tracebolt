#!/usr/bin/env python3
"""Pinned, fail-closed Tracebolt Linux release bootstrap. Run with python3 -I.

This source has no active release pin yet. A reviewed bootstrap copy must pin
the exact release manifest, attestation bundle and source revision. Keyless
verification uses an independently pinned official GitHub CLI and Sigstore root.
No CLI, manager response or environment can select executable trust.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import platform
import re
import socket
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import types
from urllib.parse import urlsplit

# Set only in a reviewed immutable official bootstrap after keyless attestation.
# Never replace this with manager-supplied configuration or a URL.
RELEASE_PIN = None
SIGNER_WORKFLOW = "storminator89/Tracebolt/.github/workflows/linux-release-candidate.yml"
GH_VERSION = "2.102.0"
GH_ARCHIVES = {
    "amd64": {"size": 15319960, "sha256": "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386"},
    "arm64": {"size": 13917794, "sha256": "7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484"},
}
# Public Sigstore root from the exact reviewed upstream Git commit:
# sigstore/root-signing 5888f358fc4ab58874447259edf83790261fc616
# targets/trusted_root.json (Git blob effb0a19e6a0b3f69b3f0a2c72b5c2a02a0ddeea).
# Embedded rather than discovered from the manager, bundle, network or host.
TRUSTED_ROOT_JSON = "{\"mediaType\":\"application/vnd.dev.sigstore.trustedroot+json;version=0.1\",\"tlogs\":[{\"baseUrl\":\"https://rekor.sigstore.dev\",\"hashAlgorithm\":\"SHA2_256\",\"publicKey\":{\"rawBytes\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\",\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"validFor\":{\"start\":\"2021-01-12T11:53:27Z\"}},\"logId\":{\"keyId\":\"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=\"}},{\"baseUrl\":\"https://log2025-1.rekor.sigstore.dev\",\"hashAlgorithm\":\"SHA2_256\",\"publicKey\":{\"rawBytes\":\"MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=\",\"keyDetails\":\"PKIX_ED25519\",\"validFor\":{\"start\":\"2025-09-23T00:00:00Z\"}},\"logId\":{\"keyId\":\"zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=\"}}],\"certificateAuthorities\":[{\"subject\":{\"organization\":\"sigstore.dev\",\"commonName\":\"sigstore\"},\"uri\":\"https://fulcio.sigstore.dev\",\"certChain\":{\"certificates\":[{\"rawBytes\":\"MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==\"}]},\"validFor\":{\"start\":\"2021-03-07T03:20:29Z\",\"end\":\"2022-12-31T23:59:59.999Z\"}},{\"subject\":{\"organization\":\"sigstore.dev\",\"commonName\":\"sigstore\"},\"uri\":\"https://fulcio.sigstore.dev\",\"certChain\":{\"certificates\":[{\"rawBytes\":\"MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=\"},{\"rawBytes\":\"MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\"}]},\"validFor\":{\"start\":\"2022-04-13T20:06:15Z\"}}],\"ctlogs\":[{\"baseUrl\":\"https://ctfe.sigstore.dev/test\",\"hashAlgorithm\":\"SHA2_256\",\"publicKey\":{\"rawBytes\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\",\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"validFor\":{\"start\":\"2021-03-14T00:00:00Z\",\"end\":\"2022-10-31T23:59:59.999Z\"}},\"logId\":{\"keyId\":\"CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=\"}},{\"baseUrl\":\"https://ctfe.sigstore.dev/2022\",\"hashAlgorithm\":\"SHA2_256\",\"publicKey\":{\"rawBytes\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==\",\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\"validFor\":{\"start\":\"2022-10-20T00:00:00Z\"}},\"logId\":{\"keyId\":\"3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4=\"}}],\"timestampAuthorities\":[{\"subject\":{\"organization\":\"sigstore.dev\",\"commonName\":\"sigstore-tsa-selfsigned\"},\"uri\":\"https://timestamp.sigstore.dev/api/v1/timestamp\",\"certChain\":{\"certificates\":[{\"rawBytes\":\"MIICEDCCAZagAwIBAgIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMC4xFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UEAxMMc2lnc3RvcmUtdHNhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ra2Z8hKNig2T9kFjCAToGG30jky+WQv3BzL+mKvh1SKNR/UwuwsfNCg4sryoYAd8E6isovVA3M4aoNdm9QDi50Z8nTEyvqgfDPtTIwXItfiW/AFf1V7uwkbkAoj0xxco2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFIn9eUOHz9BlRsMCRscsc1t9tOsDMB8GA1UdIwQYMBaAFJjsAe9/u1H/1JUeb4qImFMHic6/MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMDA2gAMGUCMDtpsV/6KaO0qyF/UMsX2aSUXKQFdoGTptQGc0ftq1csulHPGG6dsmyMNd3JB+G3EQIxAOajvBcjpJmKb4Nv+2Taoj8Uc5+b6ih6FXCCKraSqupe07zqswMcXJTe1cExvHvvlw==\"},{\"rawBytes\":\"MIIB9zCCAXygAwIBAgIUV7f0GLDOoEzIh8LXSW80OJiUp14wCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMDkxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQUQNtfRT/ou3YATa6wB/kKTe70cfJwyRIBovMnt8RcJph/COE82uyS6FmppLLL1VBPGcPfpQPYJNXzWwi8icwhKQ6W/Qe2h3oebBb2FHpwNJDqo+TMaC/tdfkv/ElJB72jRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSY7AHvf7tR/9SVHm+KiJhTB4nOvzAKBggqhkjOPQQDAwNpADBmAjEAwGEGrfGZR1cen1R8/DTVMI943LssZmJRtDp/i7SfGHmGRP6gRbuj9vOK3b67Z0QQAjEAuT2H673LQEaHTcyQSZrkp4mX7WwkmF+sVbkYY5mXN+RMH13KUEHHOqASaemYWK/E\"}]},\"validFor\":{\"start\":\"2025-07-04T00:00:00Z\"}}]}\n"
REPOSITORY = "storminator89/Tracebolt"
SCHEMA = "tracebolt.linux-release.v1"
INSTALL_ROLES = ("agent-service", "enroll-agent", "lan-agent")
ROLES = INSTALL_ROLES + ("socket-owner-reader",)
ARCHES = ("amd64", "arm64")
RUNTIME_TARGETS = ("linux-amd64",)  # ARM64 admission remains gated on native acceptance.
MAX_MANIFEST = 32 * 1024
MAX_BUNDLE = 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
MAX_SOURCE = 256 * 1024 * 1024
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?\Z")


class Rejected(Exception):
    """Safe, operator-facing failure without untrusted response content."""


def require(condition, message):
    if not condition:
        raise Rejected(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate manifest field rejected.")
        result[key] = value
    return result


def asset_names(version):
    return {f"tracebolt-{version}-linux-{arch}-{role}" for arch in ARCHES for role in ROLES} | {f"tracebolt-{version}-source.tar"}


def validate_pin(pin):
    require(type(pin) is dict and set(pin) == {"version", "sourceCommit", "manifestSHA256", "bundleSHA256"},
            "No approved signed release is pinned in this bootstrap. Distribution is not activated.")
    require(type(pin["version"]) is str and VERSION.fullmatch(pin["version"]) and len(pin["version"]) <= 64,
            "Invalid embedded release version.")
    require(type(pin["sourceCommit"]) is str and COMMIT.fullmatch(pin["sourceCommit"]), "Invalid embedded source revision.")
    require(type(pin["manifestSHA256"]) is str and HEX64.fullmatch(pin["manifestSHA256"]), "Invalid embedded manifest pin.")
    require(type(pin["bundleSHA256"]) is str and HEX64.fullmatch(pin["bundleSHA256"]), "Invalid embedded attestation bundle pin.")
    return pin



def parse_manifest(raw, pin):
    require(0 < len(raw) <= MAX_MANIFEST and digest(raw) == pin["manifestSHA256"], "Release manifest checksum mismatch.")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(Rejected("Non-JSON number rejected.")))
    except (ValueError, UnicodeError):
        raise Rejected("Invalid release manifest JSON.") from None
    require(type(value) is dict and set(value) == {"schema", "repository", "version", "sourceCommit", "runtimeTargets", "assets"},
            "Unexpected release manifest fields.")
    require(value["schema"] == SCHEMA and value["repository"] == REPOSITORY and value["version"] == pin["version"] and
            value["sourceCommit"] == pin["sourceCommit"] and value["runtimeTargets"] == list(RUNTIME_TARGETS),
            "Release identity or runtime support does not match the pinned contract.")
    assets = value["assets"]
    require(type(assets) is dict and set(assets) == asset_names(pin["version"]), "Missing or unexpected release assets.")
    for name, item in assets.items():
        limit = MAX_SOURCE if name.endswith("-source.tar") else MAX_BINARY
        require(type(item) is dict and set(item) == {"size", "sha256"} and type(item["size"]) is int and
                0 < item["size"] <= limit and type(item["sha256"]) is str and HEX64.fullmatch(item["sha256"]),
                "Invalid release asset size or checksum.")
    return value


def asset_url(version, name):
    if name in {f"gh_{GH_VERSION}_linux_{arch}.tar.gz" for arch in ARCHES}:
        return f"https://github.com/cli/cli/releases/download/v{GH_VERSION}/{name}"
    require(VERSION.fullmatch(version) and name in asset_names(version) | {"manifest.json", "manifest.sigstore.json"}, "Unexpected release asset name.")
    return f"https://github.com/{REPOSITORY}/releases/download/{version}/{name}"


def allowed_redirect(value):
    require(type(value) is str and len(value) <= 16384 and all(32 < ord(c) < 127 for c in value) and "\\" not in value,
            "Release redirect rejected.")
    target = urlsplit(value)
    require(target.scheme == "https" and target.netloc == "release-assets.githubusercontent.com" and not target.fragment and
            target.path.startswith("/github-production-release-asset/") and len(target.path) <= 2048 and
            not any(part in (".", "..") for part in target.path.split("/")), "Release redirect rejected.")
    return target


class OfficialHTTPSConnection(http.client.HTTPSConnection):
    """No ambient proxies; vet every DNS answer and dial that exact public IP."""
    def connect(self):
        require(self.host in {"github.com", "release-assets.githubusercontent.com"} and self.port == 443,
                "Non-official release destination rejected.")
        results = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        require(0 < len(results) <= 16, "Release DNS answer count is empty or exceeds its bound.")
        for family, _, _, _, address in results:
            ip = ipaddress.ip_address(address[0])
            require(family in (socket.AF_INET, socket.AF_INET6) and ip.is_global and not
                    (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified),
                    "Non-public or mixed release DNS answers rejected.")
        last = None
        for family, socktype, proto, _, address in results:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.timeout)
            try:
                sock.connect(address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as error:
                sock.close()
                last = error
        raise Rejected("Could not establish verified HTTPS to the official release host.") from last


def release_context():
    # A fixed supported-distribution system trust bundle, never SSL_CERT_FILE,
    # SSL_CERT_DIR, a manager CA, or an insecure/HTTP fallback.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    return context


def _download(version, name, output, limit, expected_size=None, expected_digest=None, connection=OfficialHTTPSConnection):
    url = asset_url(version, name)
    started = time.monotonic()
    context = release_context()
    for hop in range(2):
        target = urlsplit(url)
        conn = connection(target.hostname, 443, timeout=30, context=context)
        try:
            path = target.path + ("?" + target.query if target.query else "")
            conn.request("GET", path, headers={"User-Agent": "Tracebolt-verified-bootstrap/1", "Accept": "application/octet-stream", "Accept-Encoding": "identity"})
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                locations = [v for k, v in response.getheaders() if k.lower() == "location"]
                require(hop == 0 and len(locations) == 1, "Repeated or ambiguous release redirect rejected.")
                allowed_redirect(locations[0])
                url = locations[0]
                continue
            require(response.status == 200, "Official release asset is unavailable; no installer was run.")
            encodings = [v for k, v in response.getheaders() if k.lower() == "content-encoding"]
            require(not encodings or encodings == ["identity"], "Encoded release response rejected.")
            lengths = [v for k, v in response.getheaders() if k.lower() == "content-length"]
            transfers = [v.lower() for k, v in response.getheaders() if k.lower() == "transfer-encoding"]
            require(not transfers or (transfers == ["chunked"] and not lengths), "Ambiguous release transfer encoding rejected.")
            require(len(lengths) <= 1, "Ambiguous release response length.")
            if lengths:
                require(re.fullmatch(r"[0-9]+", lengths[0]) and 0 < int(lengths[0]) <= limit and
                        (expected_size is None or int(lengths[0]) == expected_size), "Release asset size mismatch.")
            count, checksum = 0, hashlib.sha256()
            with open_private(output) as stream:
                while True:
                    require(time.monotonic() - started < 600, "Release download exceeded its bounded time budget.")
                    chunk = response.read(min(65536, limit + 1 - count))
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= limit, "Release asset exceeds its size limit.")
                    checksum.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            require(count > 0 and (expected_size is None or count == expected_size) and
                    (not lengths or count == int(lengths[0])), "Incomplete release download.")
            require(expected_digest is None or checksum.hexdigest() == expected_digest, "Release asset checksum mismatch.")
            return
        finally:
            conn.close()
    raise Rejected("Release redirect limit exceeded.")


def _download_worker(status, arguments):
    try:
        _download(*arguments)
        status.send_bytes(b"ok")
    except BaseException as error:
        message = str(error) if isinstance(error, Rejected) else "Official HTTPS download failed; no installer was run."
        status.send_bytes(("error:" + message[:1024]).encode("utf-8"))
    finally:
        status.close()


def download(version, name, output, limit, expected_size=None, expected_digest=None, *, deadline_seconds=600):
    # A socket inactivity timeout cannot bound getaddrinfo(), slow headers or a
    # buffered read with steady byte progress. Supervise the whole read-only
    # download in a transient child. It never runs installer/service operations.
    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_download_worker, args=(sending, (version, name, output, limit, expected_size, expected_digest)))
    try:
        process.start()
        sending.close()
        process.join(deadline_seconds)
        require(not process.is_alive(), "Release download exceeded its whole-operation time budget.")
        require(process.exitcode == 0 and receiving.poll(), "Official HTTPS download worker failed; no installer was run.")
        result = receiving.recv_bytes(2048)
        require(result == b"ok", result[6:].decode("utf-8") if result.startswith(b"error:") else "Invalid download worker result.")
    finally:
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
                process.join(1)
            if process.is_alive():
                process.kill()
                process.join()
            process.close()
        receiving.close()
        sending.close()


def open_private(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "wb")


def prepare_verifier(directory, arch, fetch=download):
    require(arch in ARCHES, "Unsupported verifier architecture.")
    name = f"gh_{GH_VERSION}_linux_{arch}.tar.gz"
    selected = GH_ARCHIVES[arch]
    archive = directory / name
    fetch(GH_VERSION, name, archive, selected["size"], expected_size=selected["size"], expected_digest=selected["sha256"])
    require(file_digest(archive) == selected["sha256"], "Official verifier archive changed.")
    target = f"gh_{GH_VERSION}_linux_{arch}/bin/gh"
    found = False
    verifier = directory / "gh-verifier"
    # Copy only one exact regular member as bytes. Never extract paths, links,
    # permissions, device files or the rest of the archive onto the target.
    with tarfile.open(archive, "r:gz") as package:
        for count, member in enumerate(package):
            require(count < 1024, "Verifier archive member limit exceeded.")
            if member.name != target:
                continue
            require(not found and member.isfile() and not member.issparse() and 0 < member.size <= MAX_BINARY,
                    "Invalid or duplicate verifier member.")
            found = True
            source = package.extractfile(member)
            require(source is not None, "Missing verifier member.")
            with source, open_private(verifier) as output:
                total = 0
                while chunk := source.read(65536):
                    total += len(chunk)
                    require(total <= member.size, "Oversized verifier member.")
                    output.write(chunk)
                require(total == member.size, "Truncated verifier member.")
    require(found, "Official verifier archive did not contain the selected program.")
    os.chmod(verifier, 0o500)
    return verifier


def verify_attestation(directory, pin, verifier, runner=subprocess.run):
    require(digest((directory / "manifest.json").read_bytes()) == pin["manifestSHA256"] and
            digest((directory / "manifest.sigstore.json").read_bytes()) == pin["bundleSHA256"], "Pinned attestation inputs changed.")
    rootfile = directory / "sigstore-trusted-root.jsonl"
    with open_private(rootfile) as stream:
        stream.write(TRUSTED_ROOT_JSON.encode())
    # --bundle disables GitHub authentication. A local custom root disables TUF
    # fetching. The pinned CLI performs offline signature, certificate, log and
    # identity verification without reading the user's gh config or credentials.
    env = dict(SAFE_ENV, HOME=str(directory), GH_CONFIG_DIR=str(directory), XDG_CONFIG_HOME=str(directory),
               XDG_STATE_HOME=str(directory / "verifier-state"),
               GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1", GH_NO_EXTENSION_UPDATE_NOTIFIER="1", GH_HOST="github.com")
    args = [str(verifier), "attestation", "verify", str(directory / "manifest.json"),
            "--bundle", str(directory / "manifest.sigstore.json"), "--custom-trusted-root", str(rootfile),
            "--repo", REPOSITORY, "--signer-workflow", SIGNER_WORKFLOW,
            "--signer-digest", pin["sourceCommit"], "--source-digest", pin["sourceCommit"], "--source-ref", "refs/heads/main",
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1", "--hostname", "github.com"]
    result = runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=45)
    require(result.returncode == 0, "Release workflow provenance verification failed; no Tracebolt installer was run.")
    require(digest((directory / "manifest.json").read_bytes()) == pin["manifestSHA256"], "Release manifest changed during verification.")


def read_os_release(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z_]+)=(?:\"([^\"\\]*)\"|'([^'\\]*)'|([^\s'\"\\]+))", line)
        require(match is not None and match[1] not in values, "Unsupported or ambiguous os-release format.")
        values[match[1]] = next(value for value in match.groups()[1:] if value is not None)
    require((values.get("ID"), values.get("VERSION_ID")) in {("debian", "13"), ("ubuntu", "24.04")},
            "Supported hosts are Debian 13 or Ubuntu 24.04 only.")
    return values["ID"]


def inspect_platform():
    """Read-only native compatibility checks, without published-release admission.

    The separately approved source-acceptance harness may inspect a platform
    before that platform has earned admission to a published release. This
    function does not authorize installation or alter RUNTIME_TARGETS.
    """
    require(sys.platform == "linux", "Only Linux is supported.")
    read_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    require(architecture is not None, "Unsupported Linux architecture; amd64 or ARM64 is required.")
    require(sys.maxsize > 2**32, "A 64-bit Linux userspace and Python are required; 32-bit Raspberry Pi OS is not supported.")
    require(Path("/proc/1/comm").read_text().strip() == "systemd" and Path("/run/systemd/system").is_dir() and
            Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "A running systemd host with cgroup v2 is required.")
    require(sys.version_info >= (3, 11), "Python 3.11 or newer is required. Use the supported distribution's python3 package; no dependency was installed.")
    # Include the native installer's fixed system tools before any release asset
    # download. The installer still performs its own ownership/state checks.
    prerequisites = (("/usr/bin/curl", "curl"), ("/usr/bin/python3", "python3"),
                     ("/usr/bin/sha256sum", "coreutils"), ("/usr/bin/systemctl", "systemd"),
                     ("/usr/sbin/useradd", "passwd"), ("/usr/sbin/nologin", "login"))
    missing = [(path, package) for path, package in prerequisites
               if not Path(path).is_file() or not os.access(path, os.X_OK)]
    if not Path("/etc/ssl/certs/ca-certificates.crt").is_file():
        missing.append(("/etc/ssl/certs/ca-certificates.crt", "ca-certificates"))
    if missing:
        packages = " ".join(sorted({package for _, package in missing}))
        raise Rejected("Missing prerequisites: " + ", ".join(path for path, _ in missing) +
                       ". No dependency was installed. After administrator approval, run manually as root:\n" +
                       "apt-get update && apt-get install -- " + packages +
                       "\nThen retry the same reviewed command.")
    # Validate the fixed distribution CA bundle now, before staging or downloads.
    try:
        release_context()
    except (OSError, ssl.SSLError):
        raise Rejected("The system HTTPS CA bundle could not be loaded. Ask the administrator to inspect ca-certificates; no trust setting was changed.") from None
    return architecture


def inspect_host():
    architecture = inspect_platform()
    require("linux-" + architecture in RUNTIME_TARGETS, "This architecture is not enabled by the pinned release.")
    return architecture


def inspect_terminal():
    require(sys.stdin.isatty(), "A real foreground terminal is required; no invitation is accepted through a pipe.")
    try:
        require(os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp(),
                "Run this command in the foreground of its local terminal, then retry. No installer was started.")
        terminal = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            require(os.isatty(terminal), "The controlling terminal is unavailable; no installer was started.")
        finally:
            os.close(terminal)
    except (OSError, ValueError):
        raise Rejected("A usable local controlling terminal is required. Open a terminal and retry there; no installer was started.") from None


def inspect_staging():
    require(Path("/tmp").is_dir() and os.access("/tmp", os.W_OK | os.X_OK),
            "The fixed /tmp staging directory is unavailable or not writable. Ask the administrator to inspect it; no permissions were changed.")
    require(not os.statvfs("/tmp").f_flag & os.ST_NOEXEC,
            "The fixed /tmp staging filesystem is mounted noexec. This installer cannot run verified programs there; no mount or security setting was changed.")


def parse_args(argv):
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Download and verify the pinned official Tracebolt release. No automatic elevation or dependency installation.")
    parser.add_argument("--action", choices=("install", "upgrade", "revoke-socket-owners"), default="install")
    parser.add_argument("--apply", action="store_true", help="Explicitly authorize the selected installation or maintenance operation after verification")
    parser.add_argument("--pending-service", action="store_true")
    parser.add_argument("--upgrade-read-admin", action="store_true", help="Explicit same-identity, same-scope update of an already completed read-admin v2 installation")
    parser.add_argument("--read-admin", action="store_true", help="Fresh install with one explicit combined read-profile approval; wait for device approval and configure supported read scopes/helper")
    parser.add_argument("--read-admin-agent-origin", help="Exact public bootstrap agent ingress origin included in the combined approval")
    parser.add_argument("--resume-read-admin", action="store_true", help="Reconcile only completed phases of this exact owned read-admin installation; never replay an uncertain phase")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--manager-origin")
    parser.add_argument("--invitation-id")
    parser.add_argument("--bootstrap-sha256")
    parser.add_argument("--server-ca-base64")
    parser.add_argument("--insecure-http-test", action="store_true")
    args = parser.parse_args(argv)
    require(not args.upgrade_read_admin or args.action == "upgrade" and not args.read_admin and not args.resume_read_admin, "Read-admin upgrade requires the upgrade action and cannot install, resume or add scopes.")
    require(not args.resume_read_admin or args.read_admin, "Read-admin resume requires the same explicit read-admin profile.")
    require(not args.read_admin or args.action == "install" and not args.resume, "Read-admin is a fresh installation path; existing upgrades/native installer recovery stay separate.")
    require(bool(args.read_admin_agent_origin) == args.read_admin, "Read-admin requires its explicit public agent ingress origin; other operations cannot add that scope.")
    if args.read_admin:
        ingress = urlsplit(args.read_admin_agent_origin)
        require(len(args.read_admin_agent_origin) <= 512 and args.read_admin_agent_origin.isascii() and
                all(32 < ord(c) < 127 for c in args.read_admin_agent_origin) and
                (ingress.port is None or 0 < ingress.port <= 65535) and
                not any(c in args.read_admin_agent_origin for c in "\\%\r\n\t ") and
                ingress.scheme == ("http" if args.insecure_http_test else "https") and ingress.hostname and
                ingress.netloc == ingress.netloc.lower() and not ingress.username and not ingress.password and
                not ingress.path and not ingress.query and not ingress.fragment and
                args.read_admin_agent_origin == ingress.scheme + "://" + ingress.netloc,
                "Invalid explicitly approved agent ingress origin.")
    if args.action == "revoke-socket-owners":
        require(not any((args.read_admin, args.read_admin_agent_origin, args.resume_read_admin, args.resume, args.pending_service,
                         args.manager_origin, args.invitation_id, args.bootstrap_sha256, args.server_ca_base64, args.insecure_http_test)),
                "Socket-owner revocation accepts no enrollment, upgrade, resume or grant flags.")
    online = (args.manager_origin, args.invitation_id, args.bootstrap_sha256, args.server_ca_base64)
    if args.action == "install":
        require(all(online[:3]), "Installation requires the exact manager origin, public invitation ID and bootstrap SHA-256.")
        target = urlsplit(args.manager_origin)
        require(len(args.manager_origin) <= 2048 and target.scheme == ("http" if args.insecure_http_test else "https") and
                target.hostname and not target.username and not target.password and not target.path and not target.query and not target.fragment,
                "Invalid explicit manager origin.")
        require(re.fullmatch(r"invite_[0-9a-f]{32}", args.invitation_id) and HEX64.fullmatch(args.bootstrap_sha256), "Invalid public bootstrap identity or checksum.")
        require(bool(args.server_ca_base64) != args.insecure_http_test, "Explicit TLS public CA or disposable HTTP-test acknowledgement is required.")
        require(not args.server_ca_base64 or len(args.server_ca_base64) <= 90000, "Public manager CA input exceeds its bound.")
    else:
        require(not any(online) and not args.resume and not args.pending_service, "Upgrade preserves existing identity; enrollment and resume flags are not accepted.")
    return args


def installer_command(args, directory, manifest, arch):
    require(args.action in ("install", "upgrade"), "Maintenance cannot invoke the installer.")
    version = manifest["version"]
    path = lambda role: directory / f"tracebolt-{version}-linux-{arch}-{role}"
    source = directory / f"tracebolt-{version}-source.tar"
    command = [str(path("agent-service")), "--action", args.action, "--apply",
               "--agent-binary", str(path("lan-agent")), "--agent-sha256", manifest["assets"][path("lan-agent").name]["sha256"],
               "--enroll-binary", str(path("enroll-agent")), "--enroll-sha256", manifest["assets"][path("enroll-agent").name]["sha256"],
               "--source-archive", str(source), "--source-sha256", manifest["assets"][source.name]["sha256"]]
    for name in ("manager_origin", "invitation_id", "bootstrap_sha256", "server_ca_base64"):
        if getattr(args, name):
            command.extend(["--" + name.replace("_", "-"), getattr(args, name)])
    if args.read_admin:
        command.extend(["--require-complete-profile", "--require-agent-origin", args.read_admin_agent_origin])
    for name in ("pending_service", "resume", "insecure_http_test"):
        if getattr(args, name) and not (name == "pending_service" and args.read_admin):
            command.append("--" + name.replace("_", "-"))
    return command


def prepare_release(directory, pin, arch, fetch=download, verifier_factory=prepare_verifier, verify=verify_attestation, *, read_admin=False, maintenance=False):
    validate_pin(pin)
    require("linux-" + arch in RUNTIME_TARGETS, "This architecture is build-only; runtime installation is not enabled.")
    version = pin["version"]
    print("[2/4] Downloading the pinned release manifest and provenance verifier.", flush=True)
    fetch(version, "manifest.json", directory / "manifest.json", MAX_MANIFEST, expected_digest=pin["manifestSHA256"])
    fetch(version, "manifest.sigstore.json", directory / "manifest.sigstore.json", MAX_BUNDLE, expected_digest=pin["bundleSHA256"])
    raw = (directory / "manifest.json").read_bytes()
    verifier = verifier_factory(directory, arch, fetch)
    verify(directory, pin, verifier)
    manifest = parse_manifest(raw, pin)
    print("[3/4] Release provenance verified. Downloading and checking the selected release files.", flush=True)
    require(not (read_admin and maintenance), "Ambiguous release operation.")
    selected_roles = () if maintenance else ROLES if read_admin else INSTALL_ROLES
    names = [f"tracebolt-{version}-linux-{arch}-{role}" for role in selected_roles] + [f"tracebolt-{version}-source.tar"]
    for name in names:
        spec = manifest["assets"][name]
        fetch(version, name, directory / name, spec["size"], expected_size=spec["size"], expected_digest=spec["sha256"])
    # Re-hash every private file together before making any program executable.
    for name in names:
        path = directory / name
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600 and
                st.st_size == manifest["assets"][name]["size"] and file_digest(path) == manifest["assets"][name]["sha256"],
                "Private release staging changed before execution.")
    for name in names[:-1]:
        os.chmod(directory / name, 0o500)
    return manifest


READ_ADMIN_SOURCES = (
    "deploy/onboarding/read_admin.py", "deploy/inventory/guide.py", "deploy/journal/setup.py",
    "deploy/journal/amend.py", "deploy/journal/guide.py", "deploy/socket-owner/setup.py",
    "deploy/systemd/tracebolt-agent.service.in", "deploy/systemd/tracebolt-journal-reader.service.in",
    "deploy/systemd/tracebolt-journal-reader.socket.in",
    "deploy/systemd/tracebolt-socket-owner-reader.service.in",
    "deploy/systemd/tracebolt-socket-owner-reader.socket.in",
)


UPGRADE_SOURCE = "deploy/onboarding/upgrade.py"


def read_admin_sources(directory, manifest, *, upgrade=False):
    """Load only fixed regular members from the already provenance-verified tar.

    No archive extraction, extra download, arbitrary module/path or trust input.
    Reverify the exact source inode and hash before compiling any member.
    """
    selected_sources = READ_ADMIN_SOURCES + ((UPGRADE_SOURCE,) if upgrade else ())
    path = directory / f"tracebolt-{manifest['version']}-source.tar"
    expected = manifest["assets"][path.name]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1 and
                stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == expected["size"] and
                hashlib.file_digest(stream, "sha256").hexdigest() == expected["sha256"], "Read-admin source integrity failed.")
        stream.seek(0)
        contents, seen = {}, set()
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for member in archive:
                require(member.name not in seen and len(seen) < 10000, "Repeated or oversized source archive rejected.")
                seen.add(member.name)
                if member.name not in selected_sources:
                    continue
                require(member.isreg() and not member.issparse() and 0 < member.size <= 131072,
                        "Read-admin source member rejected.")
                source = archive.extractfile(member)
                require(source is not None, "Read-admin source member unavailable.")
                with source:
                    raw = source.read(131073)
                require(len(raw) == member.size, "Read-admin source member truncated.")
                contents[member.name] = raw
        after = os.fstat(stream.fileno())
        require(all(getattr(before, k) == getattr(after, k) == getattr(os.lstat(path), k)
                    for k in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")),
                "Read-admin source changed during verification.")
    require(set(contents) == set(selected_sources), "This release does not contain the complete reviewed read-admin workflow. No installer was run.")
    modules = []
    for name in READ_ADMIN_SOURCES[:6]:
        module = types.ModuleType("tracebolt_verified_" + name.replace("/", "_").replace(".", "_"))
        module.__file__ = "/verified-source/" + name
        exec(compile(contents[name], module.__file__, "exec"), module.__dict__)
        modules.append(module)
    templates = {Path(name).name: contents[name] for name in READ_ADMIN_SOURCES[6:]}
    if upgrade:
        module = types.ModuleType("tracebolt_verified_upgrade")
        module.__file__ = "/verified-source/" + UPGRADE_SOURCE
        exec(compile(contents[UPGRADE_SOURCE], module.__file__, "exec"), module.__dict__)
        return (*modules, templates, module)
    return (*modules, templates)


def run_read_admin(args, directory, manifest, arch, installer=None):
    workflow, inventory, setup, amendment, journal_guide, socket_setup, templates = read_admin_sources(directory, manifest)
    plan = workflow.make_plan(args, manifest, arch)
    helper_path = directory / f"tracebolt-{manifest['version']}-linux-{arch}-socket-owner-reader"
    helper_spec = dict(manifest["assets"][helper_path.name], path=str(helper_path))
    adapter = workflow.real_adapter(setup, inventory, amendment, journal_guide, socket_setup, templates, plan, helper_spec)
    command = installer_command(args, directory, manifest, arch)
    def interrupted(_signum, _frame):
        # Existing setup cleanup/retain-state handlers recognize this exception.
        # The installer temporarily replaces it with its own graceful forwarding.
        raise setup.Rejected("interrupted")
    previous = {signum: signal.signal(signum, interrupted) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = workflow.run(plan, adapter, lambda: (installer or run_installer)(command),
            inventory.confirm_terminal, inventory.emit_terminal, resume=args.resume_read_admin)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    print(json.dumps(result, indent=2))
    if result["canceled"]:
        print("Canceled before installing or granting read scopes.")
        return 0
    if result["configurationComplete"]:
        print("Read-admin configuration confirmed: inventory, network identity, all supported system-service journals and socket-owner metadata configuration. Check incoming reports in the dashboard; capability details remain in the result above.")
        return 0
    print("Read-admin setup is incomplete. Keep all installation and journal evidence; inspect the reported phase before recovery.", file=sys.stderr)
    return 1


def run_upgrade_read_admin(args, directory, manifest, arch):
    require(arch in ARCHES, "Read-admin upgrade requires a supported 64-bit Linux profile.")
    workflow, inventory, setup, amendment, _guide, socket_setup, templates, upgrade = read_admin_sources(directory, manifest, upgrade=True)
    adapter = upgrade.real_adapter(workflow, setup, inventory, amendment, socket_setup, templates, manifest, directory,
                                   installer_command(args, directory, manifest, arch), arch=arch)
    def interrupted(_signum, _frame):
        raise upgrade.Rejected("interrupted")
    previous = {signum: signal.signal(signum, interrupted) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = upgrade.run(adapter, inventory.confirm_terminal, inventory.emit_terminal)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    print(json.dumps(result, indent=2))
    if result["canceled"]:
        print("Canceled before stopping services or changing installed files.")
        return 0
    if result["completed"]:
        print("Read-admin update completed with the same identity and approved scopes. Systemd failed/start-limit bookkeeping was reset. Check new reports, journal requests and socket owners in the dashboard; native acceptance and reboot are separate.")
        return 0
    print("Read-admin update is incomplete. Preserve all receipts, upgrade evidence and private state; inspect the reported phase before recovery.", file=sys.stderr)
    return 1


def run_revoke_socket_owners(directory, manifest):
    workflow, inventory, setup, _amendment, _journal_guide, socket_setup, templates = read_admin_sources(directory, manifest)
    adapter = workflow.real_maintenance(setup, inventory, socket_setup, templates, manifest)
    def interrupted(_signum, _frame):
        raise setup.Rejected("interrupted")
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = workflow.run_revoke(adapter, inventory.confirm_terminal, inventory.emit_terminal)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps(result, indent=2))
    return 0 if result["revoked"] or result["canceled"] else 1


def run_installer(command):
    # Preserve agent-service's own cancellation/rollback contract. subprocess.run
    # would kill a child when Python receives KeyboardInterrupt; never turn an
    # ordinary Ctrl+C into SIGKILL during an installer transaction.
    child = None
    pending = []
    def forward(signum, _frame):
        if child is None:
            pending.append(signum)
        else:
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass
    previous = {signum: signal.signal(signum, forward) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        child = subprocess.Popen(command, env=SAFE_ENV)
        for signum in pending:
            forward(signum, None)
        return child.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def cleanup_release(directory, known):
    """Remove only our named files and the pinned verifier's known state leaf.

    Directory descriptors reject symlink traversal. Unknown/protected entries are
    retained; cleanup never recurses and never changes installer exit status.
    """
    complete = True
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root = os.open(directory, flags)
    except OSError:
        return False
    try:
        for name in known:
            if not isinstance(name, str) or name in ("", ".", "..") or "/" in name:
                complete = False
                continue
            try:
                os.unlink(name, dir_fd=root)
            except FileNotFoundError:
                pass
            except OSError:
                complete = False
        try:
            state = os.open("verifier-state", flags, dir_fd=root)
            try:
                try:
                    gh = os.open("gh", flags, dir_fd=state)
                except FileNotFoundError:
                    gh = None
                if gh is not None:
                    try:
                        try:
                            os.unlink("device-id", dir_fd=gh)
                        except FileNotFoundError:
                            pass
                    finally:
                        os.close(gh)
                    os.rmdir("gh", dir_fd=state)
            finally:
                os.close(state)
            os.rmdir("verifier-state", dir_fd=root)
        except FileNotFoundError:
            pass
        except OSError:
            complete = False
    finally:
        os.close(root)
    try:
        directory.rmdir()
    except OSError:
        complete = False
    return complete


def main(argv=None):
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        pin = RELEASE_PIN
        validate_pin(pin)
        arch = inspect_host()
        if not args.apply:
            print("Read-only preflight passed. No download, temporary file, enrollment or service change was made. Repeat with --apply only after authorizing the operation.")
            return 0
        require(os.getuid() == 0 and os.geteuid() == 0, "Explicit root execution is required for --apply; this program will not invoke sudo.")
        inspect_terminal()
        inspect_staging()
        print(f"[1/4] Host prerequisites passed for Tracebolt {pin['version']} on Linux {arch}. No dependency was installed. Keep this terminal open until installation finishes.", flush=True)
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix="tracebolt-release-", dir="/tmp"))
        known = asset_names(pin["version"]) | {"manifest.json", "manifest.sigstore.json", "sigstore-trusted-root.jsonl", "gh-verifier", f"gh_{GH_VERSION}_linux_{arch}.tar.gz"}
        installer_result = None
        try:
            if args.action == "revoke-socket-owners":
                manifest = prepare_release(directory, pin, arch, maintenance=True)
                installer_result = run_revoke_socket_owners(directory, manifest)
                return installer_result
            manifest = prepare_release(directory, pin, arch, read_admin=True) if args.read_admin or args.upgrade_read_admin else prepare_release(directory, pin, arch)
            print("[4/4] Provenance and all selected file hashes verified. Starting the fixed-path service installer. Enter the invitation only at its hidden terminal prompt; device approval remains a separate dashboard step.", flush=True)
            if args.upgrade_read_admin:
                installer_result = run_upgrade_read_admin(args, directory, manifest, arch)
            elif args.read_admin:
                installer_result = run_read_admin(args, directory, manifest, arch)
            else:
                installer_result = run_installer(installer_command(args, directory, manifest, arch))
            return installer_result
        finally:
            if not cleanup_release(directory, known):
                if installer_result is not None:
                    print("Tracebolt warning: Installer exit status is preserved, but private temporary download cleanup was incomplete. Do not repeat installation solely for this warning.", file=sys.stderr)
                else:
                    print("Tracebolt warning: Private temporary download cleanup was incomplete; the original operation error is preserved. No recursive cleanup or installation retry was attempted.", file=sys.stderr)
    except (Rejected, OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError, tarfile.TarError) as error:
        message = str(error) if isinstance(error, Rejected) else "Release preparation failed. Check required tools, supported host, official HTTPS access and the selected release; no automatic recovery or trust downgrade was attempted."
        print("Tracebolt: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
