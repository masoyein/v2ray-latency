#!/usr/bin/env python3

import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

import requests


# ============================================================
# Configuration
# ============================================================

SOURCE_FILES = {
    "Sub1.txt":
        "https://raw.githubusercontent.com/masoyein/v2ray-config/main/Sub1.txt",

    "top100.txt":
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
}

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray/xray")

# Small HTTPS endpoint used only for latency measurement.
TEST_URL = os.environ.get(
    "TEST_URL",
    "https://www.gstatic.com/generate_204"
)

TOP_N = 15

# Maximum time for one curl test.
TIMEOUT = 8

# Maximum time waiting for Xray's local SOCKS port.
STARTUP_TIMEOUT = 5

# 0 = test every configuration.
# Set MAX_CONFIGS=100 if you want to limit testing.
MAX_CONFIGS = int(os.environ.get("MAX_CONFIGS", "0"))

USER_AGENT = "v2ray-latency-checker/1.0"


# ============================================================
# Base64 helper
# ============================================================

def b64decode_loose(value: str) -> bytes:
    value = value.strip()
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)

    return base64.b64decode(value, validate=False)


# ============================================================
# VMess parser
# ============================================================

def decode_vmess(uri: str) -> dict:
    raw = uri.split("://", 1)[1]
    raw = raw.split("#", 1)[0]

    data = json.loads(
        b64decode_loose(raw).decode("utf-8-sig")
    )

    address = str(data.get("add") or "").strip()
    port = int(data.get("port") or 0)
    user_id = str(data.get("id") or "").strip()

    if not address or not port or not user_id:
        raise ValueError("VMess missing address/port/id")

    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "alterId": int(data.get("aid") or 0),
                            "security": str(
                                data.get("scy") or "auto"
                            ),
                        }
                    ],
                }
            ]
        },
    }

    network = str(
        data.get("net") or "tcp"
    ).lower()

    security = str(
        data.get("security")
        or data.get("tls")
        or "none"
    ).lower()

    params = {
        "type": network,
        "security": security,

        "sni": (
            data.get("sni")
            or data.get("host")
            or ""
        ),

        "host": data.get("host") or "",

        "path": data.get("path") or "/",

        "serviceName": (
            data.get("serviceName")
            or data.get("path")
            or ""
        ),

        "fp": data.get("fp") or "",
        "pbk": data.get("pbk") or "",
        "sid": data.get("sid") or "",
        "spx": data.get("spx") or "",
        "alpn": data.get("alpn") or "",

        "allowInsecure": bool(
            data.get("allowInsecure", False)
        ),

        "headerType": data.get("type") or "",
    }

    add_stream_settings(outbound, params)

    return outbound


# ============================================================
# Shadowsocks parser
# ============================================================

def parse_shadowsocks(uri: str) -> dict:
    body = uri.split("://", 1)[1]

    # Remove display name.
    body = body.split("#", 1)[0]

    # Remove optional query string.
    if "?" in body:
        body, _query = body.split("?", 1)

    if "@" in body:

        userinfo, server = body.rsplit("@", 1)

        userinfo = urllib.parse.unquote(userinfo)

        if ":" not in userinfo:
            raise ValueError(
                "Invalid Shadowsocks userinfo"
            )

        method, password = userinfo.split(":", 1)

    else:

        decoded = b64decode_loose(body).decode("utf-8")

        userinfo, server = decoded.rsplit("@", 1)

        method, password = userinfo.split(":", 1)

    # IPv6 address
    if server.startswith("["):

        end = server.find("]")

        if (
            end < 0
            or end + 1 >= len(server)
            or server[end + 1] != ":"
        ):
            raise ValueError(
                "Invalid IPv6 Shadowsocks address"
            )

        host = server[1:end]
        port = int(server[end + 2:])

    else:

        host, port_text = server.rsplit(":", 1)
        port = int(port_text)

    if not host or not port:
        raise ValueError(
            "Invalid Shadowsocks host/port"
        )

    return {
        "protocol": "shadowsocks",

        "settings": {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }
            ]
        },
    }


# ============================================================
# VLESS / Trojan / Shadowsocks URI parser
# ============================================================

def parse_uri(uri: str) -> dict:

    scheme = uri.split("://", 1)[0].lower()

    # Shadowsocks needs special parsing because many
    # ss:// URLs don't have a normal URI username/hostname.
    if scheme == "ss":
        return parse_shadowsocks(uri)

    if scheme == "vmess":
        return decode_vmess(uri)

    u = urllib.parse.urlsplit(uri)

    host = u.hostname
    port = u.port

    if not host or not port:
        raise ValueError(
            "Missing host/port"
        )

    q = urllib.parse.parse_qs(
        u.query,
        keep_blank_values=True
    )

    def q1(*names, default=""):

        for name in names:

            if name in q and q[name]:
                return q[name][0]

        return default

    network = q1(
        "type",
        "network",
        "net",
        default="tcp"
    ).lower()

    security = q1(
        "security",
        default="none"
    ).lower()

    sni = q1(
        "sni",
        "serverName",
        default=""
    )

    transport_host = q1(
        "host",
        "authority",
        default=""
    )

    path = q1(
        "path",
        default="/"
    )

    service_name = q1(
        "serviceName",
        "service",
        default=""
    )

    fingerprint = q1(
        "fp",
        "fingerprint",
        default=""
    )

    public_key = q1(
        "pbk",
        "publicKey",
        default=""
    )

    short_id = q1(
        "sid",
        "shortId",
        default=""
    )

    spider_x = q1(
        "spx",
        "spiderX",
        default=""
    )

    alpn = q1(
        "alpn",
        default=""
    )

    allow_insecure = (
        q1(
            "allowInsecure",
            "allow_insecure",
            default=""
        ).lower()
        in {"1", "true", "yes"}
    )

    # --------------------------------------------------------
    # VLESS
    # --------------------------------------------------------

    if scheme == "vless":

        user_id = urllib.parse.unquote(
            u.username or ""
        )

        if not user_id:
            raise ValueError(
                "VLESS missing UUID"
            )

        user = {
            "id": user_id,
            "encryption": q1(
                "encryption",
                default="none"
            ),
        }

        flow = q1(
            "flow",
            default=""
        )

        if flow:
            user["flow"] = flow

        outbound = {
            "protocol": "vless",

            "settings": {
                "vnext": [
                    {
                        "address": host,
                        "port": port,

                        "users": [user],
                    }
                ]
            },
        }

    # --------------------------------------------------------
    # Trojan
    # --------------------------------------------------------

    elif scheme == "trojan":

        password = urllib.parse.unquote(
            u.username or ""
        )

        if not password:
            raise ValueError(
                "Trojan missing password"
            )

        outbound = {
            "protocol": "trojan",

            "settings": {
                "servers": [
                    {
                        "address": host,
                        "port": port,
                        "password": password,
                    }
                ]
            },
        }

    else:

        raise ValueError(
            f"Unsupported scheme: {scheme}"
        )

    params = {
        "type": network,
        "security": security,

        "sni": (
            sni
            or transport_host
            or host
        ),

        "host": transport_host,

        "path": path,

        "serviceName": service_name,

        "fp": fingerprint,

        "pbk": public_key,

        "sid": short_id,

        "spx": spider_x,

        "alpn": alpn,

        "allowInsecure": allow_insecure,

        "headerType": q1(
            "headerType",
            "header",
            default=""
        ),

        "mode": q1(
            "mode",
            default=""
        ),
    }

    add_stream_settings(
        outbound,
        params
    )

    return outbound


# ============================================================
# Xray stream settings
# ============================================================

def add_stream_settings(
    outbound: dict,
    p: dict
) -> None:

    network = p["type"]
    security = p["security"]

    supported = {
        "tcp",
        "ws",
        "grpc",
        "http",
        "h2",
    }

    if network not in supported:

        raise ValueError(
            f"Unsupported transport: {network}"
        )

    stream = {
        "network": network,
        "security": security,
    }

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    if security == "tls":

        tls = {}

        if p["sni"]:
            tls["serverName"] = p["sni"]

        if p["alpn"]:

            tls["alpn"] = [
                x.strip()
                for x in p["alpn"].split(",")
                if x.strip()
            ]

        if p["fp"]:
            tls["fingerprint"] = p["fp"]

        if p["allowInsecure"]:
            tls["allowInsecure"] = True

        stream["tlsSettings"] = tls

    # --------------------------------------------------------
    # Reality
    # --------------------------------------------------------

    elif security == "reality":

        reality = {}

        mapping = {
            "sni": "serverName",
            "fp": "fingerprint",
            "pbk": "publicKey",
            "sid": "shortId",
            "spx": "spiderX",
        }

        for source_key, xray_key in mapping.items():

            if p[source_key]:

                reality[xray_key] = p[source_key]

        stream["realitySettings"] = reality

    # --------------------------------------------------------
    # WebSocket
    # --------------------------------------------------------

    if network == "ws":

        ws = {
            "path": p["path"] or "/"
        }

        if p["host"]:

            ws["headers"] = {
                "Host": p["host"]
            }

        stream["wsSettings"] = ws

    # --------------------------------------------------------
    # gRPC
    # --------------------------------------------------------

    elif network == "grpc":

        grpc = {
            "serviceName":
                p["serviceName"]
        }

        if p["host"]:

            grpc["authority"] = p["host"]

        if p["mode"] == "multi":

            grpc["multiMode"] = True

        stream["grpcSettings"] = grpc

    # --------------------------------------------------------
    # HTTP / HTTP2
    # --------------------------------------------------------

    elif network in {"http", "h2"}:

        stream["httpSettings"] = {
            "host": (
                [p["host"]]
                if p["host"]
                else []
            ),

            "path": p["path"] or "/",
        }

    # --------------------------------------------------------
    # TCP + HTTP header
    # --------------------------------------------------------

    elif (
        network == "tcp"
        and p["headerType"].lower() == "http"
    ):

        host_values = (
            [p["host"]]
            if p["host"]
            else []
        )

        stream["tcpSettings"] = {

            "header": {

                "type": "http",

                "request": {

                    "version": "1.1",

                    "method": "GET",

                    "path": [
                        p["path"] or "/"
                    ],

                    "headers": {

                        "Host": host_values,

                        "Connection": [
                            "keep-alive"
                        ],

                        "Pragma": [
                            "no-cache"
                        ],
                    },
                },
            }
        }

    outbound["streamSettings"] = stream


# ============================================================
# Extract V2Ray links from source files
# ============================================================

def extract_uris(text: str) -> list[str]:

    lines = [
        x.strip()
        for x in text
        .replace("\r", "")
        .split("\n")
        if x.strip()
    ]

    schemes = (
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
    )

    found = [
        x
        for x in lines
        if x.lower().startswith(schemes)
    ]

    if found:
        return found

    # Some subscription files are Base64 encoded.
    compact = re.sub(
        r"\s+",
        "",
        text
    )

    try:

        decoded = (
            b64decode_loose(compact)
            .decode("utf-8-sig")
        )

        return [
            x.strip()
            for x in decoded
            .replace("\r", "")
            .split("\n")
            if x.strip().lower().startswith(
                schemes
            )
        ]

    except Exception:

        return []


# ============================================================
# Duplicate removal
# ============================================================

def canonical_key(uri: str) -> str:

    if "://" in uri:

        scheme, rest = uri.split(
            "://",
            1
        )

        # Remove display name (#...)
        rest = rest.split(
            "#",
            1
        )[0]

        return (
            f"{scheme.lower()}://{rest}"
        )

    return uri.strip()


# ============================================================
# Download + merge both sources
# ============================================================

def load_sources():

    all_items = []

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT
    })

    for source_name, url in SOURCE_FILES.items():

        print(
            f"[SOURCE] {source_name}"
        )

        response = session.get(
            url,
            timeout=30
        )

        response.raise_for_status()

        uris = extract_uris(
            response.text
        )

        print(
            f"  found {len(uris)} configs"
        )

        for uri in uris:

            all_items.append(
                (source_name, uri)
            )

    unique = {}

    for source_name, uri in all_items:

        key = canonical_key(uri)

        if key not in unique:

            unique[key] = (
                source_name,
                uri
            )

        else:

            old_source, old_uri = \
                unique[key]

            if source_name not in old_source:

                unique[key] = (
                    old_source
                    + "+"
                    + source_name,
                    old_uri
                )

    items = list(
        unique.values()
    )

    if MAX_CONFIGS:

        items = items[
            :MAX_CONFIGS
        ]

    print(
        f"[MERGE] unique configs: "
        f"{len(items)}"
    )

    return items


# ============================================================
# Find a free local port
# ============================================================

def free_port() -> int:

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as s:

        s.bind(
            ("127.0.0.1", 0)
        )

        return int(
            s.getsockname()[1]
        )


# ============================================================
# Wait for Xray SOCKS port
# ============================================================

def wait_port(
    port: int,
    timeout: float
) -> bool:

    deadline = (
        time.monotonic()
        + timeout
    )

    while (
        time.monotonic()
        < deadline
    ):

        try:

            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.25
            ):
                return True

        except OSError:

            time.sleep(0.05)

    return False


# ============================================================
# Test one configuration
# ============================================================

def test_one(
    source: str,
    uri: str
) -> dict:

    port = free_port()

    with tempfile.TemporaryDirectory(
        prefix="xray-test-"
    ) as td:

        config_path = (
            Path(td)
            / "config.json"
        )

        config = {

            "log": {
                "loglevel": "none"
            },

            "inbounds": [

                {
                    "listen":
                        "127.0.0.1",

                    "port":
                        port,

                    "protocol":
                        "socks",

                    "settings": {

                        "auth":
                            "noauth",

                        "udp":
                            False,
                    },
                }
            ],

            "outbounds": [
                parse_uri(uri)
            ],
        }

        config_path.write_text(
            json.dumps(
                config,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        # Check configuration first.
        check = subprocess.run(

            [
                XRAY_BIN,
                "run",
                "-test",
                "-config",
                str(config_path),
            ],

            capture_output=True,

            text=True,

            timeout=10,
        )

        if check.returncode != 0:

            raise ValueError(
                "Xray config rejected"
            )

        # Start Xray.
        proc = subprocess.Popen(

            [
                XRAY_BIN,
                "run",
                "-config",
                str(config_path),
            ],

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL,
        )

        try:

            if not wait_port(
                port,
                STARTUP_TIMEOUT
            ):

                raise TimeoutError(
                    "Xray SOCKS inbound "
                    "did not start"
                )

            # ------------------------------------------------
            # curl through Xray SOCKS5
            #
            # --socks5-hostname means DNS is also resolved
            # through the proxy tunnel.
            # ------------------------------------------------

            command = [

                "curl",

                "-sS",

                "--http1.1",

                "--connect-timeout",
                "4",

                "--max-time",
                str(TIMEOUT),

                "--socks5-hostname",
                f"127.0.0.1:{port}",

                "-A",
                USER_AGENT,

                "-o",
                "/dev/null",

                "-w",
                "%{http_code} %{time_total}",

                TEST_URL,
            ]

            started = time.perf_counter()

            result = subprocess.run(

                command,

                capture_output=True,

                text=True,

                timeout=TIMEOUT + 2,
            )

            elapsed_ms = (
                time.perf_counter()
                - started
            ) * 1000.0

            if result.returncode != 0:

                raise ConnectionError(
                    result.stderr.strip()
                    or "curl failed"
                )

            parts = (
                result.stdout
                .strip()
                .split()
            )

            if len(parts) < 2:

                raise ConnectionError(
                    "Invalid curl timing output"
                )

            status = int(
                parts[0]
            )

            measured_ms = (
                float(parts[1])
                * 1000.0
            )

            if status >= 400:

                raise ConnectionError(
                    f"HTTP status {status}"
                )

            return {

                "source":
                    source,

                "config":
                    uri,

                "latency_ms":
                    round(
                        measured_ms,
                        2
                    ),

                "http_status":
                    status,

                "elapsed_ms":
                    round(
                        elapsed_ms,
                        2
                    ),
            }

        finally:

            proc.terminate()

            try:

                proc.wait(
                    timeout=2
                )

            except subprocess.TimeoutExpired:

                proc.kill()

                proc.wait()


# ============================================================
# Main
# ============================================================

def main():

    if not Path(
        XRAY_BIN
    ).exists():

        raise SystemExit(
            f"Xray binary not found: "
            f"{XRAY_BIN}"
        )

    items = load_sources()

    results = []

    failed = 0

    total = len(items)

    for index, (
        source,
        uri
    ) in enumerate(
        items,
        1
    ):

        try:

            result = test_one(
                source,
                uri
            )

            results.append(
                result
            )

            print(
                f"[{index}/{total}] "
                f"{result['latency_ms']:.0f} ms  "
                f"{source}"
            )

        except Exception as exc:

            failed += 1

            print(
                f"[{index}/{total}] "
                f"FAIL {source}: "
                f"{exc}"
            )

    # Lowest latency first.
    results.sort(
        key=lambda x:
            x["latency_ms"]
    )

    top = results[
        :TOP_N
    ]

    # --------------------------------------------------------
    # top15.txt
    # --------------------------------------------------------

    Path(
        "top15.txt"
    ).write_text(

        "\n".join(
            item["config"]
            for item in top
        )
        + (
            "\n"
            if top
            else ""
        ),

        encoding="utf-8"
    )

    # --------------------------------------------------------
    # latency_report.json
    # --------------------------------------------------------

    report = {

        "generated_at_utc":
            time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime()
            ),

        "test_url":
            TEST_URL,

        "total_unique_configs":
            total,

        "successful_tests":
            len(results),

        "failed_tests":
            failed,

        "top":
            top,
    }

    Path(
        "latency_report.json"
    ).write_text(

        json.dumps(
            report,
            ensure_ascii=False,
            indent=2
        ),

        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Console summary
    # --------------------------------------------------------

    print()
    print(
        f"SUCCESS: {len(results)}"
    )

    print(
        f"FAILED:  {failed}"
    )

    print(
        f"TOP 15:  {len(top)}"
    )

    print()

    for rank, item in enumerate(
        top,
        1
    ):

        print(
            f"{rank:2}. "
            f"{item['latency_ms']:8.2f} ms  "
            f"{item['source']}"
        )


if __name__ == "__main__":
    main()
