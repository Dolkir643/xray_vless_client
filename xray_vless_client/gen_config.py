#!/usr/bin/env python3
"""
Генерирует config.json для Xray из VLESS-ссылки (формат Shadowrocket / стандартный).
Использование: VLESS_URL='vless://...' SOCKS_PORT=1080 python3 gen_config.py > /path/config.json
"""
import base64
import json
import os
import sys
from urllib.parse import parse_qs, urlparse


def _decode_netloc(netloc: str) -> str:
    """Если netloc в Base64 (Shadowrocket) — декодируем и возвращаем uuid@host:port."""
    if "@" in netloc:
        return netloc
    try:
        decoded = base64.b64decode(netloc, validate=True).decode("utf-8", errors="replace")
        # Shadowrocket: "auto:uuid@host:port" или "uuid@host:port"
        if decoded.startswith("auto:"):
            decoded = decoded[5:]
        return decoded
    except Exception:
        return netloc


def parse_vless_url(url: str) -> dict:
    """Парсит vless://uuid@host:port?params или vless://BASE64?params (Shadowrocket)."""
    if not url or not url.strip().startswith("vless://"):
        raise ValueError("Нужна ссылка вида vless://uuid@host:port?params")

    parsed = urlparse(url.strip())
    if parsed.scheme != "vless":
        raise ValueError("Схема должна быть vless://")

    netloc = _decode_netloc(parsed.netloc)
    if "@" not in netloc:
        raise ValueError("Формат: vless://uuid@host:port или vless://BASE64(...)?params")
    uuid_part, host_port = netloc.rsplit("@", 1)
    uuid = uuid_part.strip()
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str.strip())
        except ValueError:
            raise ValueError("Порт должен быть числом")
    else:
        host = host_port.strip()
        port = 443

    query = parse_qs(parsed.query or "", keep_blank_values=True)

    def q(key: str, default: str = "") -> str:
        return (query.get(key) or [default])[0].strip()

    # Shadowrocket: peer=SNI, tls=1, xtls=2, pbk=..., sid=... → reality/tls
    sni = q("sni") or q("peer") or host
    security = q("security", "none").lower()
    if not security or security == "none":
        if q("pbk") and q("sid"):
            security = "reality"
        elif q("tls") in ("1", "true", "yes") or q("xtls"):
            security = "tls"

    alpn_raw = q("alpn")
    alpn = alpn_raw.split(",") if alpn_raw else ["h2", "http/1.1"]

    return {
        "address": host,
        "port": port,
        "id": uuid,
        "encryption": "none",
        "flow": q("flow") or ("xtls-rprx-vision" if security == "reality" else None),
        "type": q("type", "tcp"),
        "security": security,
        "sni": sni,
        "fp": q("fp", "chrome"),
        "pbk": q("pbk"),
        "sid": q("sid"),
        "host": q("host"),
        "path": q("path", "/"),
        "alpn": alpn,
    }


def build_xray_config(vless: dict, socks_port: int) -> dict:
    """Собирает полный config.json для Xray: inbound SOCKS, outbound VLESS."""
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": vless["address"],
                    "port": vless["port"],
                    "users": [
                        {
                            "id": vless["id"],
                            "encryption": vless["encryption"],
                            **({"flow": vless["flow"]} if vless.get("flow") else {}),
                        }
                    ],
                }
            ]
        },
        "streamSettings": {},
        "tag": "proxy",
    }

    # streamSettings: network
    net = vless.get("type") or "tcp"
    outbound["streamSettings"]["network"] = net

    # streamSettings: security (reality / tls / none)
    sec = (vless.get("security") or "none").lower()
    if sec == "reality":
        outbound["streamSettings"]["security"] = "reality"
        outbound["streamSettings"]["realitySettings"] = {
            "serverName": vless.get("sni") or vless["address"],
            "fingerprint": vless.get("fp") or "chrome",
            "publicKey": vless.get("pbk") or "",
            "shortId": vless.get("sid") or "",
            "show": False,
        }
    elif sec == "tls":
        outbound["streamSettings"]["security"] = "tls"
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": vless.get("sni") or vless["address"],
            "fingerprint": vless.get("fp") or "chrome",
            "alpn": vless.get("alpn", ["h2", "http/1.1"]),
        }
    # else none — не задаём security

    # ws / grpc / http и т.д.
    if net == "ws":
        outbound["streamSettings"]["wsSettings"] = {
            "path": vless.get("path") or "/",
            "headers": {"Host": vless.get("host") or vless["address"]},
        }
    elif net == "grpc":
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": vless.get("path") or "grpc",
        }
    elif net == "http":
        outbound["streamSettings"]["httpSettings"] = {
            "path": vless.get("path") or "/",
            "host": [vless.get("host") or vless["address"]],
        }

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "0.0.0.0",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": False},
            }
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}
            ],
        },
    }
    return config


def main() -> None:
    url = os.environ.get("VLESS_URL", "").strip()
    try:
        socks_port = int(os.environ.get("SOCKS_PORT", "1080"))
    except ValueError:
        socks_port = 1080

    if not url:
        print("Задайте переменную VLESS_URL (vless://...)", file=sys.stderr)
        sys.exit(1)

    try:
        vless = parse_vless_url(url)
    except ValueError as e:
        print(f"Ошибка разбора VLESS-ссылки: {e}", file=sys.stderr)
        sys.exit(2)

    cfg = build_xray_config(vless, socks_port)
    json.dump(cfg, sys.stdout, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
