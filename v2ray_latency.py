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
# CONFIGURATION
# ============================================================

SOURCES = {
    "Sub1.txt":
        "https://raw.githubusercontent.com/masoyein/v2ray-config/main/Sub1.txt",

    "top100.txt":
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
}

XRAY = os.environ.get(
    "XRAY_BIN",
    "./xray/xray"
)

TEST_URL = os.environ.get(
    "TEST_URL",
    "https://www.gstatic.com/generate_204"
)

TOP_N = 15

TIMEOUT = int(
    os.environ.get("TIMEOUT", "8")
)

MAX_CONFIGS = int(
    os.environ.get("MAX_CONFIGS", "0")
)

USER_AGENT = (
    "v2ray-latency-checker/2.0"
)


# ============================================================
# HELPERS
# ============================================================

def b64(value: str) -> bytes:

    value = re.sub(
        r"\s+",
        "",
        value
    )

    value = value.replace(
        "-",
        "+"
    ).replace(
        "_",
        "/"
    )

    value += "=" * (
        -len(value) % 4
    )

    return base64.b64decode(
        value,
        validate=False
    )


def bool_value(value) -> bool:

    if isinstance(value, bool):
        return value

    return str(
        value or ""
    ).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def q1(
    query,
    *names,
    default=""
):

    for name in names:

        if (
            name in query
            and query[name]
        ):
            return query[name][0]

    return default


# ============================================================
# TRANSPORT NORMALIZATION
# ============================================================

def normalize_method(
    value
) -> str:

    value = str(
        value or "raw"
    ).strip().lower()

    aliases = {

        "tcp":
            "raw",

        "raw":
            "raw",

        "none":
            "raw",

        "ws":
            "websocket",

        "websocket":
            "websocket",

        "grpc":
            "grpc",

        "httpupgrade":
            "httpupgrade",

        "http-upgrade":
            "httpupgrade",

        "xhttp":
            "xhttp",

        "splithttp":
            "xhttp",

        "h2":
            "h2",

        "http":
            "h2",

        "kcp":
            "mkcp",

        "mkcp":
            "mkcp",
    }

    return aliases.get(
        value,
        value
    )


# ============================================================
# BUILD XRAY STREAM SETTINGS
# ============================================================

def build_stream_settings(
    p: dict
) -> dict:

    method = normalize_method(
        p.get("type")
    )

    security = str(
        p.get("security")
        or "none"
    ).strip().lower()

    supported = {
        "raw",
        "xhttp",
        "grpc",
        "websocket",
        "httpupgrade",
        "h2",
        "mkcp",
    }

    if method not in supported:

        raise ValueError(
            f"Unsupported transport: {method}"
        )

    if security not in {
        "none",
        "tls",
        "reality",
    }:

        raise ValueError(
            f"Unsupported security: {security}"
        )

    # REALITY is supported by
    # RAW / XHTTP / gRPC.
    if (
        security == "reality"
        and method not in {
            "raw",
            "xhttp",
            "grpc",
        }
    ):

        raise ValueError(
            "REALITY is not supported "
            f"with {method}"
        )

    stream = {

        "method":
            method,

        "security":
            security,
    }

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    if security == "tls":

        tls = {}

        if p.get("sni"):

            tls[
                "serverName"
            ] = p["sni"]

        if p.get("alpn"):

            tls["alpn"] = [
                x.strip()
                for x in str(
                    p["alpn"]
                ).split(",")

                if x.strip()
            ]

        if p.get("fp"):

            tls[
                "fingerprint"
            ] = p["fp"]

        if p.get(
            "allowInsecure"
        ):

            tls[
                "allowInsecure"
            ] = True

        stream[
            "tlsSettings"
        ] = tls

    # --------------------------------------------------------
    # REALITY
    # --------------------------------------------------------

    if security == "reality":

        reality = {}

        mapping = {

            "sni":
                "serverName",

            "fp":
                "fingerprint",

            "pbk":
                "publicKey",

            "sid":
                "shortId",

            "spx":
                "spiderX",
        }

        for source, target in (
            mapping.items()
        ):

            if p.get(source):

                reality[target] = (
                    p[source]
                )

        if not reality.get(
            "publicKey"
        ):

            raise ValueError(
                "REALITY missing "
                "publicKey/pbk"
            )

        stream[
            "realitySettings"
        ] = reality

    # --------------------------------------------------------
    # RAW
    # --------------------------------------------------------

    if method == "raw":

        header_type = str(
            p.get("headerType")
            or ""
        ).lower()

        if header_type == "http":

            stream[
                "rawSettings"
            ] = {

                "header": {

                    "type":
                        "http",

                    "request": {

                        "version":
                            "1.1",

                        "method":
                            "GET",

                        "path": [
                            p.get(
                                "path"
                            ) or "/"
                        ],

                        "headers": {

                            "Host": (
                                [p["host"]]
                                if p.get("host")
                                else []
                            ),

                            "Connection": [
                                "keep-alive"
                            ],

                            "Pragma": [
                                "no-cache"
                            ],
                        },
                    },
                },
            }

        else:

            stream[
                "rawSettings"
            ] = {

                "header": {
                    "type": "none"
                }
            }

    # --------------------------------------------------------
    # WEBSOCKET
    # --------------------------------------------------------

    elif method == "websocket":

        ws = {

            "path":
                p.get("path")
                or "/"
        }

        if p.get("host"):

            ws[
                "headers"
            ] = {

                "Host":
                    p["host"]
            }

        stream[
            "wsSettings"
        ] = ws

    # --------------------------------------------------------
    # gRPC
    # --------------------------------------------------------

    elif method == "grpc":

        grpc = {

            "serviceName":
                p.get(
                    "serviceName"
                )
                or ""
        }

        if p.get("mode") == "multi":

            grpc[
                "multiMode"
            ] = True

        if p.get("host"):

            grpc[
                "authority"
            ] = p["host"]

        stream[
            "grpcSettings"
        ] = grpc

    # --------------------------------------------------------
    # HTTP UPGRADE
    # --------------------------------------------------------

    elif method == "httpupgrade":

        httpupgrade = {

            "path":
                p.get("path")
                or "/"
        }

        if p.get("host"):

            httpupgrade[
                "host"
            ] = p["host"]

        if p.get("headers"):

            httpupgrade[
                "headers"
            ] = p["headers"]

        stream[
            "httpupgradeSettings"
        ] = httpupgrade

    # --------------------------------------------------------
    # XHTTP
    # --------------------------------------------------------

    elif method == "xhttp":

        xhttp = {

            "path":
                p.get("path")
                or "/"
        }

        if p.get("host"):

            xhttp[
                "host"
            ] = p["host"]

        if p.get("mode"):

            xhttp[
                "mode"
            ] = p["mode"]

        if p.get("extra"):

            try:

                xhttp[
                    "extra"
                ] = json.loads(
                    p["extra"]
                )

            except Exception as exc:

                raise ValueError(
                    "Invalid XHTTP "
                    f"extra JSON: {exc}"
                )

        stream[
            "xhttpSettings"
        ] = xhttp

    # --------------------------------------------------------
    # HTTP/2
    # --------------------------------------------------------

    elif method == "h2":

        stream[
            "httpSettings"
        ] = {

            "host": (
                [p["host"]]
                if p.get("host")
                else []
            ),

            "path":
                p.get("path")
                or "/",
        }

    # --------------------------------------------------------
    # mKCP
    # --------------------------------------------------------

    elif method == "mkcp":

        stream[
            "kcpSettings"
        ] = {

            "mtu":
                int(
                    p.get("mtu")
                    or 1350
                ),

            "tti":
                int(
                    p.get("tti")
                    or 50
                ),

            "uplinkCapacity":
                int(
                    p.get(
                        "uplinkCapacity"
                    )
                    or 5
                ),

            "downlinkCapacity":
                int(
                    p.get(
                        "downlinkCapacity"
                    )
                    or 20
                ),

            "cwndMultiplier":
                int(
                    p.get(
                        "cwndMultiplier"
                    )
                    or 1
                ),

            "maxSendingWindow":
                int(
                    p.get(
                        "maxSendingWindow"
                    )
                    or 2097152
                ),
        }

    return stream


# ============================================================
# VMESS
# ============================================================

def parse_vmess(
    uri: str
) -> dict:

    encoded = (
        uri
        .split("://", 1)[1]
        .split("#", 1)[0]
    )

    data = json.loads(
        b64(encoded).decode(
            "utf-8-sig"
        )
    )

    address = str(
        data.get("add")
        or ""
    ).strip()

    port = int(
        data.get("port")
        or 0
    )

    user_id = str(
        data.get("id")
        or ""
    ).strip()

    if (
        not address
        or not port
        or not user_id
    ):

        raise ValueError(
            "VMess missing "
            "address/port/id"
        )

    security = (
        data.get("security")
        or data.get("tls")
        or "none"
    )

    if security is True:
        security = "tls"

    if str(
        security
    ).lower() in {
        "",
        "0",
        "false",
    }:

        security = "none"

    params = {

        "type":
            data.get("net")
            or data.get("network")
            or "tcp",

        "security":
            security,

        "sni":
            data.get("sni")
            or data.get("serverName")
            or data.get("host")
            or address,

        "host":
            data.get("host")
            or "",

        "path":
            data.get("path")
            or "/",

        "serviceName":
            data.get("serviceName")
            or "",

        "fp":
            data.get("fp")
            or data.get("fingerprint")
            or "",

        "pbk":
            data.get("pbk")
            or data.get("publicKey")
            or "",

        "sid":
            data.get("sid")
            or data.get("shortId")
            or "",

        "spx":
            data.get("spx")
            or data.get("spiderX")
            or "",

        "alpn":
            data.get("alpn")
            or "",

        "allowInsecure":
            bool_value(
                data.get(
                    "allowInsecure"
                )
            ),

        "headerType":
            data.get("headerType")
            or data.get("type")
            or "",

        "mode":
            data.get("mode")
            or "",

        "extra":
            data.get("extra")
            or "",

        "mtu":
            data.get("mtu"),

        "tti":
            data.get("tti"),

        "uplinkCapacity":
            data.get(
                "uplinkCapacity"
            ),

        "downlinkCapacity":
            data.get(
                "downlinkCapacity"
            ),

        "cwndMultiplier":
            data.get(
                "cwndMultiplier"
            ),

        "maxSendingWindow":
            data.get(
                "maxSendingWindow"
            ),
    }

    return {

        "protocol":
            "vmess",

        "settings": {

            "vnext": [

                {

                    "address":
                        address,

                    "port":
                        port,

                    "users": [

                        {

                            "id":
                                user_id,

                            "alterId":
                                int(
                                    data.get(
                                        "aid"
                                    )
                                    or 0
                                ),

                            "security":
                                str(
                                    data.get(
                                        "scy"
                                    )
                                    or "auto"
                                ),
                        }
                    ],
                }
            ]
        },

        "streamSettings":
            build_stream_settings(
                params
            ),
    }


# ============================================================
# SHADOWSOCKS
# ============================================================

def parse_shadowsocks(
    uri: str
) -> dict:

    parsed = urllib.parse.urlsplit(
        uri
    )

    body = (
        parsed.netloc
        + parsed.path
    )

    if "@" in body:

        auth, server = (
            body.rsplit(
                "@",
                1
            )
        )

        auth = urllib.parse.unquote(
            auth
        )

    else:

        decoded = b64(
            body
        ).decode(
            "utf-8"
        )

        if "@" not in decoded:

            raise ValueError(
                "Invalid Shadowsocks URI"
            )

        auth, server = (
            decoded.rsplit(
                "@",
                1
            )
        )

    if ":" not in auth:

        raise ValueError(
            "Invalid Shadowsocks "
            "method/password"
        )

    method_name, password = (
        auth.split(
            ":",
            1
        )
    )

    if server.startswith("["):

        end = server.find("]")

        if (
            end < 0
            or end + 1 >= len(server)
            or server[end + 1] != ":"
        ):

            raise ValueError(
                "Invalid Shadowsocks "
                "IPv6 address"
            )

        host = server[
            1:end
        ]

        port = int(
            server[
                end + 2:
            ]
        )

    else:

        host, port = (
            server.rsplit(
                ":",
                1
            )
        )

        port = int(port)

    query = urllib.parse.parse_qs(
        parsed.query
    )

    if "plugin" in query:

        raise ValueError(
            "Shadowsocks plugin "
            "transport is not supported"
        )

    return {

        "protocol":
            "shadowsocks",

        "settings": {

            "servers": [

                {

                    "address":
                        host,

                    "port":
                        port,

                    "method":
                        method_name,

                    "password":
                        password,
                }
            ]
        },
    }


# ============================================================
# VLESS / TROJAN
# ============================================================

def parse_uri(
    uri: str
) -> dict:

    scheme = (
        uri
        .split("://", 1)[0]
        .lower()
    )

    if scheme == "vmess":

        return parse_vmess(
            uri
        )

    if scheme == "ss":

        return parse_shadowsocks(
            uri
        )

    if scheme not in {
        "vless",
        "trojan",
    }:

        raise ValueError(
            f"Unsupported scheme: "
            f"{scheme}"
        )

    parsed = urllib.parse.urlsplit(
        uri
    )

    host = parsed.hostname
    port = parsed.port

    if not host or not port:

        raise ValueError(
            "Missing host/port"
        )

    query = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    transport_host = q1(
        query,
        "host",
        "authority",
        default=""
    )

    params = {

        "type":
            q1(
                query,
                "type",
                "network",
                "net",
                default="raw"
            ),

        "security":
            q1(
                query,
                "security",
                default="none"
            ),

        "sni":
            q1(
                query,
                "sni",
                "serverName",
                default=""
            )
            or transport_host
            or host,

        "host":
            transport_host,

        "path":
            q1(
                query,
                "path",
                default="/"
            ),

        "serviceName":
            q1(
                query,
                "serviceName",
                "service",
                default=""
            ),

        "fp":
            q1(
                query,
                "fp",
                "fingerprint",
                default=""
            ),

        "pbk":
            q1(
                query,
                "pbk",
                "publicKey",
                default=""
            ),

        "sid":
            q1(
                query,
                "sid",
                "shortId",
                default=""
            ),

        "spx":
            q1(
                query,
                "spx",
                "spiderX",
                default=""
            ),

        "alpn":
            q1(
                query,
                "alpn",
                default=""
            ),

        "mode":
            q1(
                query,
                "mode",
                default=""
            ),

        "extra":
            q1(
                query,
                "extra",
                default=""
            ),

        "headerType":
            q1(
                query,
                "headerType",
                "header",
                default=""
            ),

        "allowInsecure":
            bool_value(
                q1(
                    query,
                    "allowInsecure",
                    "allow_insecure",
                    default=""
                )
            ),

        "mtu":
            q1(
                query,
                "mtu",
                default=""
            ),

        "tti":
            q1(
                query,
                "tti",
                default=""
            ),

        "uplinkCapacity":
            q1(
                query,
                "uplinkCapacity",
                default=""
            ),

        "downlinkCapacity":
            q1(
                query,
                "downlinkCapacity",
                default=""
            ),

        "cwndMultiplier":
            q1(
                query,
                "cwndMultiplier",
                default=""
            ),

        "maxSendingWindow":
            q1(
                query,
                "maxSendingWindow",
                default=""
            ),
    }

    # Optional custom HTTP headers.
    raw_headers = q1(
        query,
        "headers",
        default=""
    )

    if raw_headers:

        try:

            headers = json.loads(
                raw_headers
            )

            if isinstance(
                headers,
                dict
            ):

                params[
                    "headers"
                ] = {

                    str(k):
                        str(v)

                    for k, v
                    in headers.items()
                }

        except Exception:
            pass

    # --------------------------------------------------------
    # VLESS
    # --------------------------------------------------------

    if scheme == "vless":

        user_id = urllib.parse.unquote(
            parsed.username
            or ""
        )

        if not user_id:

            raise ValueError(
                "VLESS missing UUID"
            )

        user = {

            "id":
                user_id,

            "encryption":
                q1(
                    query,
                    "encryption",
                    default="none"
                ),
        }

        flow = q1(
            query,
            "flow",
            default=""
        )

        if flow:

            user[
                "flow"
            ] = flow

        outbound = {

            "protocol":
                "vless",

            "settings": {

                "vnext": [

                    {

                        "address":
                            host,

                        "port":
                            port,

                        "users": [
                            user
                        ],
                    }
                ]
            },
        }

    # --------------------------------------------------------
    # TROJAN
    # --------------------------------------------------------

    else:

        password = urllib.parse.unquote(
            parsed.username
            or ""
        )

        if not password:

            raise ValueError(
                "Trojan missing password"
            )

        outbound = {

            "protocol":
                "trojan",

            "settings": {

                "servers": [

                    {

                        "address":
                            host,

                        "port":
                            port,

                        "password":
                            password,
                    }
                ]
            },
        }

    outbound[
        "streamSettings"
    ] = build_stream_settings(
        params
    )

    return outbound


# ============================================================
# EXTRACT CONFIG LINKS
# ============================================================

def extract_uris(
    text: str
) -> list:

    lines = [

        x.strip()

        for x in text
        .replace(
            "\r",
            ""
        )
        .splitlines()

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

        if x.lower().startswith(
            schemes
        )
    ]

    if found:

        return found

    # Subscription may itself be Base64.
    try:

        decoded = b64(
            re.sub(
                r"\s+",
                "",
                text
            )
        ).decode(
            "utf-8-sig"
        )

        return [

            x.strip()

            for x in decoded.splitlines()

            if x.strip()
            .lower()
            .startswith(
                schemes
            )
        ]

    except Exception:

        return []


# ============================================================
# DEDUPLICATION
# ============================================================

def canonical_key(
    uri: str
) -> str:

    if "://" in uri:

        scheme, rest = (
            uri.split(
                "://",
                1
            )
        )

        # Remove display name only.
        rest = rest.split(
            "#",
            1
        )[0]

        return (
            scheme.lower()
            + "://"
            + rest.strip()
        )

    return uri.strip()


# ============================================================
# LOAD + MERGE SOURCES
# ============================================================

def load_sources():

    all_items = []

    session = requests.Session()

    session.headers.update({

        "User-Agent":
            USER_AGENT
    })

    for source_name, url in (
        SOURCES.items()
    ):

        print(
            f"[SOURCE] "
            f"{source_name}"
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
            f"  found "
            f"{len(uris)} configs"
        )

        for uri in uris:

            all_items.append(
                (
                    source_name,
                    uri
                )
            )

    unique = {}

    source_map = {}

    for source_name, uri in (
        all_items
    ):

        key = canonical_key(
            uri
        )

        if key not in unique:

            unique[key] = uri

            source_map[key] = set()

        source_map[
            key
        ].add(
            source_name
        )

    items = [

        (
            "+".join(
                sorted(
                    source_map[key]
                )
            ),

            uri
        )

        for key, uri
        in unique.items()
    ]

    if MAX_CONFIGS:

        items = items[
            :MAX_CONFIGS
        ]

    print(
        "[MERGE] unique configs: "
        f"{len(items)}"
    )

    return items


# ============================================================
# LOCAL PORT
# ============================================================

def free_port() -> int:

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as sock:

        sock.bind(
            (
                "127.0.0.1",
                0
            )
        )

        return sock.getsockname()[1]


def wait_port(
    port: int,
    timeout: float = 5
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
                (
                    "127.0.0.1",
                    port
                ),
                timeout=0.25
            ):

                return True

        except OSError:

            time.sleep(
                0.05
            )

    return False


# ============================================================
# FAILURE CLASSIFICATION
# ============================================================

def classify_error(
    message: str
) -> str:

    m = message.lower()

    if (
        "unsupported transport"
        in m
    ):

        return (
            "unsupported_transport"
        )

    if (
        "config rejected"
        in m
    ):

        return (
            "xray_config_rejected"
        )

    if (
        "timeout"
        in m
    ):

        return "timeout"

    if (
        "connection reset"
        in m
    ):

        return (
            "connection_reset"
        )

    if (
        "ssl"
        in m
        or "tls"
        in m
    ):

        return "tls_error"

    if (
        "plugin"
        in m
    ):

        return (
            "unsupported_plugin"
        )

    if (
        "curl"
        in m
    ):

        return "curl_error"

    return "other"


# ============================================================
# TEST ONE CONFIG
# ============================================================

def test_one(
    source: str,
    uri: str
) -> dict:

    port = free_port()

    with tempfile.TemporaryDirectory(
        prefix="xray-test-"
    ) as temp_dir:

        config_path = (
            Path(temp_dir)
            / "config.json"
        )

        log_path = (
            Path(temp_dir)
            / "xray.log"
        )

        config = {

            "log": {

                "loglevel":
                    "warning"
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

                parse_uri(
                    uri
                )
            ],
        }

        config_path.write_text(

            json.dumps(
                config,
                ensure_ascii=False
            ),

            encoding="utf-8"
        )

        # ----------------------------------------------------
        # Xray configuration validation
        # ----------------------------------------------------

        check = subprocess.run(

            [

                XRAY,

                "run",

                "-test",

                "-config",

                str(
                    config_path
                ),
            ],

            capture_output=True,

            text=True,

            timeout=10,
        )

        if check.returncode != 0:

            detail = (

                check.stderr.strip()

                or

                check.stdout.strip()

                or

                "unknown Xray error"
            )

            raise ValueError(

                "Xray config rejected: "
                + detail[-800:]
            )

        # ----------------------------------------------------
        # Start Xray
        # ----------------------------------------------------

        with log_path.open(
            "w",
            encoding="utf-8"
        ) as log_file:

            process = subprocess.Popen(

                [

                    XRAY,

                    "run",

                    "-config",

                    str(
                        config_path
                    ),
                ],

                stdout=log_file,

                stderr=subprocess.STDOUT,
            )

        try:

            if not wait_port(
                port
            ):

                tail = (
                    log_path
                    .read_text(
                        encoding="utf-8",
                        errors="replace"
                    )[-600:]
                )

                raise TimeoutError(

                    "Xray SOCKS inbound "
                    "did not start "
                    + tail
                )

            # ------------------------------------------------
            # HTTPS request through Xray SOCKS5
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

            try:

                result = subprocess.run(

                    command,

                    capture_output=True,

                    text=True,

                    timeout=TIMEOUT + 2,
                )

            except subprocess.TimeoutExpired:

                raise TimeoutError(
                    "curl timeout"
                )

            if result.returncode != 0:

                raise ConnectionError(

                    result.stderr.strip()

                    or

                    "curl failed"
                )

            parts = (
                result.stdout
                .strip()
                .split()
            )

            if len(parts) != 2:

                raise ConnectionError(
                    "Invalid curl timing output"
                )

            status = int(
                parts[0]
            )

            seconds = float(
                parts[1]
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
                        seconds * 1000,
                        2
                    ),

                "http_status":
                    status,
            }

        finally:

            process.terminate()

            try:

                process.wait(
                    timeout=2
                )

            except subprocess.TimeoutExpired:

                process.kill()

                process.wait()


# ============================================================
# MAIN
# ============================================================

def main():

    if not Path(
        XRAY
    ).exists():

        raise SystemExit(

            "Xray binary not found: "
            f"{XRAY}"
        )

    items = load_sources()

    successful = []

    failed = []

    total = len(
        items
    )

    # --------------------------------------------------------
    # Test every configuration
    # --------------------------------------------------------

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

            successful.append(
                result
            )

            print(

                f"[{index}/{total}] "

                f"{result['latency_ms']:.0f} ms  "

                f"{source}"
            )

        except Exception as exc:

            message = str(
                exc
            )

            failure_type = (
                classify_error(
                    message
                )
            )

            failed.append({

                "source":
                    source,

                "reason":
                    failure_type,

                "error":
                    message[-800:],
            })

            print(

                f"[{index}/{total}] "

                f"FAIL {source}: "

                f"{failure_type}: "

                f"{message[:250]}"
            )

    # --------------------------------------------------------
    # Sort lowest latency first
    # --------------------------------------------------------

    successful.sort(

        key=lambda item:
            item["latency_ms"]
    )

    top = successful[
        :TOP_N
    ]

    # --------------------------------------------------------
    # Write top15.txt
    # --------------------------------------------------------

    Path(
        "top15.txt"
    ).write_text(

        "".join(

            item["config"]
            + "\n"

            for item in top
        ),

        encoding="utf-8"
    )

    # --------------------------------------------------------
    # Failure summary
    # --------------------------------------------------------

    failure_summary = {}

    for item in failed:

        reason = item[
            "reason"
        ]

        failure_summary[
            reason
        ] = (

            failure_summary.get(
                reason,
                0
            )
            + 1
        )

    # --------------------------------------------------------
    # Write latency_report.json
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
            len(successful),

        "failed_tests":
            len(failed),

        "failure_summary":
            failure_summary,

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
        "================================"
    )

    print(
        f"TOTAL:   {total}"
    )

    print(
        f"SUCCESS: {len(successful)}"
    )

    print(
        f"FAILED:  {len(failed)}"
    )

    print(
        f"TOP 15:  {len(top)}"
    )

    print(
        "================================"
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
