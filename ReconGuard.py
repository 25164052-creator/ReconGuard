#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║                        ReconGuard — Pure Python Recon Tool                ║
║                                                                            ║
║  أداة استطلاع أمني شاملة تعمل بـ Pure Python (Standard Library فقط)       ║
║  تدعم: DNS / WHOIS / HTTP / SSL / Port Scan / Subdomains / Regex / Report  ║
║                                                                            ║
║  Author : عبدالرحمن محمد الحازي                                              ║
║  Version: 2.0.0                                                            ║
║  License: MIT                                                              ║
╚══════════════════════════════════════════════════════════════════════════╝

WARNING: This tool is for authorized security testing and educational
purposes ONLY. Unauthorized scanning of systems you do not own or have
explicit permission to test is illegal and unethical.
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import re
import socket
import ssl
import struct
import sys
import time
import random
import string
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ─────────────────────────────────────────────────────────────────────────────
#  Version & Metadata
# ─────────────────────────────────────────────────────────────────────────────

__version__ = "2.0.0"
__author__ = "عبدالرحمن محمد الحازي"
__tool_name__ = "ReconGuard"

# ─────────────────────────────────────────────────────────────────────────────
#  Custom Exceptions
# ─────────────────────────────────────────────────────────────────────────────


class ReconError(Exception):
    """Base exception for all tool errors."""


class ConfigError(ReconError):
    """Configuration file errors."""


class ValidationError(ReconError):
    """Input validation errors."""


class NetworkError(ReconError):
    """Network-related errors (timeout, connection refused, DNS failure)."""


class PermissionError(ReconError):
    """Permission-related errors."""


class ReportError(ReconError):
    """Report generation errors."""


# ─────────────────────────────────────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class DnsRecordSet:
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    soa_records: List[str] = field(default_factory=list)


@dataclass
class WhoIsResult:
    domain: str
    primary_nameserver: str = "N/A"
    responsible_mail: str = "N/A"
    serial_number: str = "N/A"
    error: Optional[str] = None


@dataclass
class IpGeoResult:
    domain: str
    resolved_ip: str = "N/A"
    country: str = "N/A"
    city: str = "N/A"
    isp: str = "N/A"
    asn: str = "N/A"
    error: Optional[str] = None


@dataclass
class SslInfo:
    domain: str
    valid_from: str = "Unknown"
    valid_until: str = "Unknown"
    issuer: str = "Unknown"
    subject: str = "Unknown"
    san: List[str] = field(default_factory=list)
    serial_number: str = "Unknown"
    error: Optional[str] = None


@dataclass
class PortScanResult:
    open_ports: Dict[int, str] = field(default_factory=dict)
    total_scanned: int = 0
    error: Optional[str] = None


@dataclass
class HttpResult:
    url: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    technologies: List[str] = field(default_factory=list)
    cms: Optional[str] = None
    content_preview: str = ""
    is_json: bool = False
    json_sample: Optional[Any] = None
    redirects: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TargetReport:
    domain: str
    http: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    whois: Optional[Dict[str, Any]] = None
    geo: Optional[Dict[str, Any]] = None
    ssl: Optional[Dict[str, Any]] = None
    ports: Optional[Dict[str, Any]] = None
    subdomains: Optional[List[str]] = None
    security_headers: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────────────────────────────────────

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

# Color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

    @staticmethod
    def is_supported() -> bool:
        """Check if terminal supports colors."""
        return (
            sys.stdout.isatty()
            and platform.system() != "Windows"
            or (platform.system() == "Windows" and os.environ.get("WT_SESSION"))
        )

    @classmethod
    def get(cls, color: str) -> str:
        if not cls.is_supported():
            return ""
        return getattr(cls, color.upper(), "")


# ─────────────────────────────────────────────────────────────────────────────
#  Console Output Helper
# ─────────────────────────────────────────────────────────────────────────────


class Console:
    """Centralized console output with logging integration."""

    _logger: Optional[logging.Logger] = None

    @classmethod
    def init_logger(cls, level: str = "INFO"):
        log_level = LOG_LEVELS.get(level.upper(), logging.INFO)
        logger = logging.getLogger(__tool_name__)
        logger.setLevel(log_level)
        if not logger.handlers:
            handler = logging.NullHandler()
            logger.addHandler(handler)
        logger.propagate = False
        cls._logger = logger

    @staticmethod
    def _c(color: str) -> str:
        return Colors.get(color)

    @staticmethod
    def _r() -> str:
        return Colors.get("reset")

    @staticmethod
    def info(msg: str):
        c = Colors.get("cyan")
        r = Colors.get("reset")
        print(f"{c}[*]{r} {msg}")
        if Console._logger:
            Console._logger.info(msg)

    @staticmethod
    def success(msg: str):
        c = Colors.get("green")
        r = Colors.get("reset")
        print(f"{c}[+]{r} {msg}")
        if Console._logger:
            Console._logger.info(f"[+] {msg}")

    @staticmethod
    def warning(msg: str):
        c = Colors.get("yellow")
        r = Colors.get("reset")
        print(f"{c}[!]{r} {msg}")
        if Console._logger:
            Console._logger.warning(msg)

    @staticmethod
    def error(msg: str):
        c = Colors.get("red")
        r = Colors.get("reset")
        print(f"{c}[-]{r} {msg}", file=sys.stderr)
        if Console._logger:
            Console._logger.error(msg)

    @staticmethod
    def debug(msg: str):
        c = Colors.get("gray")
        r = Colors.get("reset")
        if Console._logger and Console._logger.level <= logging.DEBUG:
            print(f"{c}[D]{r} {msg}")
        if Console._logger:
            Console._logger.debug(msg)

    @staticmethod
    def banner():
        c1 = Colors.get("cyan")
        c2 = Colors.get("magenta")
        r = Colors.get("reset")
        print(f"""
{c1}╔═══════════════════════════════════════════════════════════════╗
{c1}║{c2}  ReconGuard v{__version__} — Pure Python Security Recon  {c1}║
{c1}║{c2}  Standard Library Only — No Third-Party Dependencies     {c1}║
{c1}╚═══════════════════════════════════════════════════════════════╝{r}
""")

    @staticmethod
    def separator(title: str = ""):
        line = "─" * 50
        c = Colors.get("gray")
        r = Colors.get("reset")
        if title:
            print(f"\n{c}{line}{r}")
            print(f"  {title}")
            print(f"{c}{line}{r}")
        else:
            print(f"{c}{line}{r}")


# ─────────────────────────────────────────────────────────────────────────────
#  Utility Functions
# ─────────────────────────────────────────────────────────────────────────────


def clean_domain(raw: str) -> Optional[str]:
    """Normalize and validate a domain string."""
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip().lower()
    if not raw:
        return None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    raw = raw.strip()
    if raw and "." in raw and not raw.startswith(".") and not raw.endswith("."):
        # Basic validation: no spaces, valid chars
        if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', raw):
            return raw
    return None


def is_valid_port(port: int) -> bool:
    return 0 < port <= 65535


def validate_ports(ports: List[int]) -> List[int]:
    """Validate and deduplicate port list."""
    valid = set()
    for p in ports:
        if isinstance(p, (int, float)) and is_valid_port(int(p)):
            valid.add(int(p))
    return sorted(valid)


# ─────────────────────────────────────────────────────────────────────────────
#  Raw DNS Protocol Client (No dnspython — Pure Standard Library)
# ─────────────────────────────────────────────────────────────────────────────

# DNS Record Types
DNS_TYPE_A = 1
DNS_TYPE_NS = 2
DNS_TYPE_CNAME = 5
DNS_TYPE_SOA = 6
DNS_TYPE_PTR = 12
DNS_TYPE_MX = 15
DNS_TYPE_TXT = 16
DNS_TYPE_AAAA = 28

# DNS Response Codes
DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5

TYPE_NAMES = {
    DNS_TYPE_A: "A",
    DNS_TYPE_NS: "NS",
    DNS_TYPE_CNAME: "CNAME",
    DNS_TYPE_SOA: "SOA",
    DNS_TYPE_PTR: "PTR",
    DNS_TYPE_MX: "MX",
    DNS_TYPE_TXT: "TXT",
    DNS_TYPE_AAAA: "AAAA",
}

TYPE_IDS = {v: k for k, v in TYPE_NAMES.items()}


class DnsClient:
    """Minimal DNS client implementing RFC 1035 over UDP — Pure Standard Library."""

    # Well-known public DNS servers
    PUBLIC_DNS_SERVERS = [
        ("8.8.8.8", 53),       # Google
        ("1.1.1.1", 53),       # Cloudflare
        ("8.8.4.4", 53),       # Google secondary
        ("1.0.0.1", 53),       # Cloudflare secondary
        ("9.9.9.9", 53),       # Quad9
        ("208.67.222.222", 53),# OpenDNS
    ]

    def __init__(self, timeout: float = 5.0, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        self._server_idx = 0

    def _build_query(self, domain: str, qtype: int) -> bytes:
        """Build a DNS query packet per RFC 1035."""
        # Transaction ID (random 16-bit)
        txn_id = random.randint(0, 65535)

        # Flags: standard query, recursion desired
        flags = 0x0100  # RD=1

        # Header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
        header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

        # Question section
        question = self._encode_name(domain)
        question += struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN

        return header + question

    def _encode_name(self, name: str) -> bytes:
        """Encode domain name as DNS label sequence."""
        parts = name.rstrip(".").split(".")
        result = b""
        for part in parts:
            label = part.encode("ascii", errors="replace")
            length = len(label)
            if length > 63:
                label = label[:63]
                length = 63
            result += struct.pack("!B", length) + label
        result += b"\x00"  # Null terminator
        return result

    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parse a domain name from DNS response, handling compression pointers."""
        labels = []
        original_offset = offset
        jumped = False
        jump_offset = 0
        max_jumps = 10
        jumps = 0

        while True:
            if offset >= len(data):
                break
            length = data[offset]

            if length == 0:
                offset += 1
                break

            # Compression pointer (top 2 bits set)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset:offset+2])[0]
                pointer &= 0x3FFF  # Mask off the 2 flag bits
                if not jumped:
                    jump_offset = offset + 2
                jumped = True
                offset = pointer
                jumps += 1
                if jumps > max_jumps:
                    break
                continue

            offset += 1
            if offset + length > len(data):
                break
            label = data[offset:offset+length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

        name = ".".join(labels)
        next_offset = jump_offset if jumped else offset
        return name, next_offset

    def _parse_response(self, data: bytes, qtype: int) -> List[str]:
        """Parse DNS response and extract answer records."""
        results = []

        if len(data) < 12:
            return results

        # Parse header
        txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])

        # Check response code
        rcode = flags & 0x0F
        if rcode == DNS_RCODE_NXDOMAIN:
            return results
        if rcode == DNS_RCODE_SERVFAIL:
            return results
        if rcode != DNS_RCODE_NOERROR:
            return results

        offset = 12

        # Skip question section
        for _ in range(qdcount):
            _, offset = self._parse_name(data, offset)
            offset += 4  # QTYPE(2) + QCLASS(2)

        # Parse answer section
        for _ in range(ancount):
            name, offset = self._parse_name(data, offset)
            if offset + 10 > len(data):
                break

            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10

            if offset + rdlength > len(data):
                break

            rdata = data[offset:offset+rdlength]

            if rtype == DNS_TYPE_A and rdlength == 4:
                ip = ".".join(str(b) for b in rdata)
                results.append(ip)

            elif rtype == DNS_TYPE_AAAA and rdlength == 16:
                # Format IPv6 address
                parts = []
                for i in range(0, 16, 2):
                    parts.append(f"{rdata[i]:02x}{rdata[i+1]:02x}")
                ip6 = ":".join(parts)
                results.append(ip6)

            elif rtype == DNS_TYPE_CNAME:
                cname, _ = self._parse_name(data, offset)
                if cname:
                    results.append(cname)

            elif rtype == DNS_TYPE_NS:
                ns_name, _ = self._parse_name(data, offset)
                if ns_name:
                    results.append(ns_name)

            elif rtype == DNS_TYPE_MX:
                if rdlength >= 2:
                    preference = struct.unpack("!H", rdata[:2])[0]
                    mx_name, _ = self._parse_name(data, offset + 2)
                    if mx_name:
                        results.append(f"{mx_name} (pref={preference})")

            elif rtype == DNS_TYPE_TXT:
                txt_parts = []
                pos = 0
                while pos < rdlength:
                    if pos >= len(rdata):
                        break
                    txt_len = rdata[pos]
                    pos += 1
                    if pos + txt_len > len(rdata):
                        txt_len = len(rdata) - pos
                    txt_parts.append(rdata[pos:pos+txt_len].decode("utf-8", errors="replace"))
                    pos += txt_len
                if txt_parts:
                    results.append("".join(txt_parts))

            elif rtype == DNS_TYPE_SOA:
                mname, soa_offset = self._parse_name(data, offset)
                rname, soa_offset = self._parse_name(data, soa_offset)
                if soa_offset + 20 <= len(data):
                    serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[soa_offset:soa_offset+20])
                    results.append(f"mname={mname} rname={rname} serial={serial}")
                    # Also extract as structured for WhoIs
                    results.append(f"__soa_mname__={mname}")
                    results.append(f"__soa_rname__={rname}")
                    results.append(f"__soa_serial__={serial}")

            offset += rdlength

        return results

    def query_udp(self, domain: str, qtype: int) -> List[str]:
        """Perform a raw DNS query over UDP and return list of string results."""
        query = self._build_query(domain, qtype)

        last_error = None
        servers_to_try = self.PUBLIC_DNS_SERVERS.copy()
        # Start with the current server index, then try others
        if self._server_idx > 0:
            servers_to_try = servers_to_try[self._server_idx:] + servers_to_try[:self._server_idx]

        for attempt in range(self.retries + 1):
            for server_ip, server_port in servers_to_try:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    sock.sendto(query, (server_ip, server_port))

                    data, _ = sock.recvfrom(4096)
                    sock.close()
                    sock = None

                    if len(data) < 12:
                        continue

                    # Verify transaction ID matches
                    resp_txn_id = struct.unpack("!H", data[:2])[0]
                    query_txn_id = struct.unpack("!H", query[:2])[0]
                    if resp_txn_id != query_txn_id:
                        continue

                    return self._parse_response(data, qtype)

                except socket.timeout:
                    last_error = f"DNS timeout querying {server_ip}"
                except OSError as exc:
                    last_error = f"DNS error ({server_ip}): {exc}"
                finally:
                    if sock:
                        try:
                            sock.close()
                        except OSError:
                            pass

        if last_error:
            Console.debug(f"DNS UDP failed for {domain} {TYPE_NAMES.get(qtype, qtype)}: {last_error}")
        return []

    # ── DNS-over-HTTPS (DoH) — primary method, uses urllib only ──────────

    DOH_ENDPOINTS = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net:5053/dns-query",
    ]

    # DoH type name mapping
    DOH_TYPE_NAMES = {
        DNS_TYPE_A: "A",
        DNS_TYPE_NS: "NS",
        DNS_TYPE_CNAME: "CNAME",
        DNS_TYPE_SOA: "SOA",
        DNS_TYPE_MX: "MX",
        DNS_TYPE_TXT: "TXT",
        DNS_TYPE_AAAA: "AAAA",
    }

    def query_doh(self, domain: str, qtype: int) -> List[str]:
        """Perform DNS query via DNS-over-HTTPS (DoH) using urllib."""
        type_name = self.DOH_TYPE_NAMES.get(qtype, str(qtype))

        for endpoint in self.DOH_ENDPOINTS:
            try:
                params = urlencode({"name": domain, "type": type_name})
                url = f"{endpoint}?{params}"
                req = Request(url, headers={
                    "User-Agent": f"ReconGuard/{__version__}",
                    "Accept": "application/dns-json",
                })
                with urlopen(req, timeout=self.timeout) as resp:
                    if resp.getcode() != 200:
                        continue
                    data = json.loads(resp.read().decode("utf-8"))

                    if data.get("Status", 5) != 0:
                        continue

                    results: List[str] = []
                    for answer in data.get("Answer", []):
                        ans_type = answer.get("type", 0)
                        ans_data = answer.get("data", "")

                        if qtype == DNS_TYPE_MX:
                            # DoH returns MX as "10 mail.example.com."
                            results.append(ans_data.rstrip("."))
                        elif qtype == DNS_TYPE_TXT:
                            results.append(ans_data.strip('"'))
                        elif qtype == DNS_TYPE_SOA:
                            # DoH returns SOA as "mname rname serial refresh retry expire minimum"
                            parts = ans_data.split()
                            if len(parts) >= 3:
                                mname = parts[0].rstrip(".")
                                rname = parts[1].rstrip(".")
                                serial = parts[2]
                                results.append(f"mname={mname} rname={rname} serial={serial}")
                                results.append(f"__soa_mname__={mname}")
                                results.append(f"__soa_rname__={rname}")
                                results.append(f"__soa_serial__={serial}")
                            else:
                                results.append(ans_data)
                        else:
                            # For A, AAAA, NS, CNAME — return the data directly
                            results.append(ans_data.rstrip("."))

                    return sorted(set(results))

            except (URLError, socket.timeout, json.JSONDecodeError, OSError) as exc:
                Console.debug(f"DoH query failed ({endpoint}): {exc}")
                continue

        Console.debug(f"DoH query exhausted for {domain} {type_name}")
        return []

    def query(self, domain: str, qtype: int) -> List[str]:
        """Perform a DNS query — tries DoH first, falls back to raw UDP protocol."""
        # Method 1: DNS-over-HTTPS (most reliable in restricted networks)
        results = self.query_doh(domain, qtype)
        if results:
            return results

        # Method 2: Raw UDP DNS protocol (fallback)
        results = self.query_udp(domain, qtype)
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  Task 1: Domain Cleanup Pipeline
# ─────────────────────────────────────────────────────────────────────────────


def task_1_domain_pipeline(domains: List[str]) -> List[str]:
    """Clean, normalize, and deduplicate a list of domain strings."""
    cleaned: Set[str] = set()
    invalid_count = 0
    for d in domains:
        domain = clean_domain(d)
        if domain:
            cleaned.add(domain)
        else:
            invalid_count += 1
            if d and d.strip():
                Console.debug(f"Invalid domain skipped: '{d}'")

    result = sorted(cleaned)
    Console.info(f"Domain pipeline: {len(result)} valid domain(s)" +
                 (f", {invalid_count} invalid skipped" if invalid_count else ""))
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Task 2: HTTP Reconnaissance (using urllib — no requests library)
# ─────────────────────────────────────────────────────────────────────────────

TECH_DETECTION_RULES: Dict[str, List[str]] = {
    "Nginx": ["nginx"],
    "Apache": ["apache", "httpd"],
    "IIS": ["iis", "microsoft-iis"],
    "Cloudflare": ["cloudflare"],
    "Caddy": ["caddy"],
    "OpenResty": ["openresty"],
    "Traefik": ["traefik"],
    "LiteSpeed": ["litespeed"],
    "Node.js": ["node.js", "nodejs", "express"],
    "Python": ["python", "wsgi", "gunicorn", "flask", "django"],
    "Ruby": ["ruby", "phusion", "passenger"],
    "Java": ["java", "servlet", "jakarta", "tomcat", "jetty", "jboss"],
    "Go": ["golang", "go-http-server"],
    "PHP": ["php"],
    "ASP.NET": ["asp.net", "aspx"],
    "WordPress": ["wordpress"],
    "Joomla": ["joomla"],
    "Drupal": ["drupal"],
    "Magento": ["magento"],
    "Laravel": ["laravel"],
    "Django": ["django"],
    "Flask": ["flask"],
    "Express": ["express"],
    "Next.js": ["next.js", "nextjs", "x-nextjs"],
    "Vercel": ["vercel"],
    "Nuxt.js": ["nuxt"],
    "Gatsby": ["gatsby"],
    "React": ["react"],
    "Vue.js": ["vue"],
    "Angular": ["angular"],
}

SECURITY_HEADERS_MAP = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-permitted-cross-domain-policies": "X-Permitted-Cross-Domain-Policies",
}


def _detect_technologies(headers: Dict[str, str], body: str = "") -> List[str]:
    """Detect web technologies from response headers and body."""
    techs: List[str] = []
    server_val = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "").lower()
    combined = f"{server_val} {powered_by}"

    for name, patterns in TECH_DETECTION_RULES.items():
        for pat in patterns:
            if pat in combined:
                techs.append(name)
                break

    # Cloudflare via CF-Ray header
    if "CF-Ray" in headers or "cf-ray" in headers:
        if "Cloudflare" not in techs:
            techs.append("Cloudflare")

    # Vercel via x-vercel-id
    if "x-vercel-id" in headers:
        if "Vercel" not in techs:
            techs.append("Vercel")

    # WordPress detection from body
    if "WordPress" not in techs:
        wp_markers = ["wp-content", "wp-json", "wp-includes", "yoast", "wp-meta"]
        if any(marker in body.lower() for marker in wp_markers):
            techs.append("WordPress")

    # Joomla detection from body
    if "Joomla" not in techs:
        joomla_markers = ["joomla", "com_content", "/components/com_"]
        if any(marker in body.lower() for marker in joomla_markers):
            techs.append("Joomla")

    # Drupal detection from body
    if "Drupal" not in techs:
        drupal_markers = ["drupal", "drupal.js", "sites/all/"]
        if any(marker in body.lower() for marker in drupal_markers):
            techs.append("Drupal")

    return sorted(set(techs))


def _check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check presence of security-related HTTP headers."""
    present = {}
    missing = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_name, display_name in SECURITY_HEADERS_MAP.items():
        if header_name in lower_headers:
            present[display_name] = lower_headers[header_name]
        else:
            missing.append(display_name)

    return {
        "present": present,
        "missing": missing,
        "security_score": f"{len(present)}/{len(SECURITY_HEADERS_MAP)}",
    }


def _http_request(url: str, timeout: int = 15) -> Optional[HttpResult]:
    """Perform HTTP request using urllib (no requests library)."""
    result = HttpResult(url=url)

    # SSL context that doesn't verify (for recon purposes)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }

    req = Request(url, headers=headers, method="GET")

    try:
        resp = urlopen(req, timeout=timeout, context=ctx)
        result.status_code = resp.getcode()
        result.headers = dict(resp.headers.items())
        content = resp.read()
        result.content_length = len(content)
        content_text = content.decode("utf-8", errors="replace")[:15000]
        result.content_preview = content_text
        result.is_json = "application/json" in resp.headers.get("Content-Type", "").lower()
        if result.is_json:
            try:
                import json as _json
                result.json_sample = _json.loads(content_text)
            except (ValueError, json.JSONDecodeError):
                result.json_sample = None

        # Detect technologies
        result.technologies = _detect_technologies(dict(resp.headers.items()), content_text)
        result.cms = "WordPress" if "WordPress" in result.technologies else None

        # Track redirects
        if hasattr(resp, 'url') and resp.url != url:
            result.redirects = [resp.url]

        return result

    except HTTPError as exc:
        result.status_code = exc.code
        result.error = f"HTTP {exc.code}: {exc.reason}"
        try:
            content = exc.read()
            content_text = content.decode("utf-8", errors="replace")[:10000]
            result.content_preview = content_text
            result.headers = dict(exc.headers.items()) if exc.headers else {}
            result.technologies = _detect_technologies(result.headers, content_text)
        except Exception:
            pass
        return result

    except URLError as exc:
        result.error = f"URL Error: {exc.reason}"
        return result

    except socket.timeout:
        result.error = f"Connection timed out ({timeout}s)"
        return result

    except Exception as exc:
        result.error = f"Request failed: {exc}"
        return result


def task_2_http_recon(
    domain: str,
    endpoint: str = "",
    additional_endpoints: Optional[List[str]] = None,
    timeout: int = 15,
) -> Optional[Dict[str, Any]]:
    """Perform HTTP request to domain+endpoint with failover."""
    urls_to_try: List[str] = []
    endpoints = [endpoint] if endpoint else [""]
    if additional_endpoints:
        endpoints.extend(additional_endpoints)

    for scheme in ["https://", "http://"]:
        for ep in endpoints:
            ep_clean = ep.lstrip("/")
            url = f"{scheme}{domain}/{ep_clean}".rstrip("/")
            urls_to_try.append(url)

    # Try all URLs; prefer 2xx/3xx responses, but fall back to any response with content
    best_result = None
    all_endpoints_results = []

    for url in urls_to_try:
        Console.debug(f"HTTP trying: {url}")
        result = _http_request(url, timeout)

        if result and result.status_code > 0:
            tech_str = ", ".join(result.technologies) if result.technologies else "none"
            status = result.status_code
            ep_name = url.split(domain + "/", 1)[1] if domain + "/" in url else "/"

            if 200 <= status < 400:
                Console.success(
                    f"HTTP: {domain} [{ep_name}] -> {status} ({tech_str})"
                )
                return asdict(result)
            elif best_result is None or (result.content_length > 0 and best_result.content_length == 0):
                best_result = result
            all_endpoints_results.append({"endpoint": ep_name, "status": status, "url": url})

    # Return best available result (even if 4xx/5xx) if we found anything
    if best_result:
        tech_str = ", ".join(best_result.technologies) if best_result.technologies else "none"
        Console.success(
            f"HTTP: {domain} [{endpoint or '/'}] -> "
            f"{best_result.status_code} ({tech_str})"
        )
        result_dict = asdict(best_result)
        result_dict["all_endpoints_checked"] = all_endpoints_results
        return result_dict

    Console.error(f"HTTP recon failed for {domain}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Task 3: Regex Extraction
# ─────────────────────────────────────────────────────────────────────────────

# Default regex patterns for secret/credential detection
DEFAULT_REGEX_PATTERNS: Dict[str, str] = {
    "linkfinder_endpoints": r"""(?:\"|')((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\.[a-zA-Z]{2,}[^\"']{0,}|(?:/|\.\./|\./)[^\"'><,;| *()(%\$^/\\[\]][^\"'><,;|()]{1,}|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^\"|']{0,}|)|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^\"|']{0,}|)|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^\"|']{0,}|))(?:\"|')""",
    "tokens": r"Bearer\s+([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+)",
    "api_keys": r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
    "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "internal_ips": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "google_api": r"AIza[0-9A-Za-z-_]{35}",
    "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "google_captcha": r"6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
    "google_oauth": r"ya29\.[0-9A-Za-z\-_]+",
    "amazon_aws_access_key_id": r"A[SK]IA[0-9A-Z]{16}",
    "amazon_mws_auth_token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "amazon_aws_url": r"s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com",
    "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "authorization_basic": r"basic [a-zA-Z0-9=:_+/-]{5,100}",
    "authorization_bearer": r"bearer [a-zA-Z0-9_\-..=:_+/]{5,100}",
    "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
    "twilio_api_key": r"SK[0-9a-fA-F]{32}",
    "twilio_account_sid": r"AC[a-zA-Z0-9_\-]{32}",
    "stripe_standard_api": r"sk_live_[0-9a-zA-Z]{24}",
    "github_access_token": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
    "rsa_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
    "json_web_token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
    "slack_token": r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"',
    "possible_creds": r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)",
}


def task_3_regex_extraction(
    raw_corpus: str,
    patterns: Dict[str, str],
    case_insensitive_keys: Optional[Set[str]] = None,
) -> Dict[str, List[str]]:
    """Apply regex patterns to a corpus and return sorted unique matches."""
    if case_insensitive_keys is None:
        case_insensitive_keys = {"api_keys", "emails", "possible_creds"}

    results: Dict[str, List[str]] = {}
    total_findings = 0

    for name, pattern in patterns.items():
        try:
            flags = re.IGNORECASE if name in case_insensitive_keys else 0
            matches = re.findall(pattern, raw_corpus, flags)

            # Handle tuple results from groups
            cleaned_matches: List[str] = []
            for m in matches:
                if isinstance(m, tuple):
                    for g in m:
                        if g:
                            cleaned_matches.append(str(g))
                elif m:
                    cleaned_matches.append(str(m))

            unique = sorted(set(cleaned_matches))
            results[name] = unique

            if unique:
                Console.success(f"Regex '{name}': {len(unique)} match(es)")
                total_findings += len(unique)

        except re.error as exc:
            Console.error(f"Regex '{name}' compile error: {exc}")
            results[name] = []

    Console.info(f"Regex extraction complete: {total_findings} total findings")
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  Task 4: JSON Schema Transformer
# ─────────────────────────────────────────────────────────────────────────────


def task_4_json_transformer(json_input_path: str, json_output_path: str) -> int:
    """Transform an API inventory JSON into a normalized schema."""
    input_file = Path(json_input_path)
    if not input_file.is_file():
        raise ValidationError(f"Input file not found: {json_input_path}")

    try:
        with input_file.open("r", encoding="utf-8") as f:
            source = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Invalid JSON in input file: {exc}")
    except OSError as exc:
        raise ValidationError(f"Cannot read input file: {exc}")

    items = source.get("items", source) if isinstance(source, dict) else source
    if not isinstance(items, list):
        items = [items] if isinstance(items, dict) else []

    records: List[Dict[str, Any]] = []
    source_version = source.get("version", "1.0") if isinstance(source, dict) else "1.0"

    for item in items:
        if not isinstance(item, dict):
            continue
        entity_id = str(item.get("id") or item.get("uuid") or "UNKNOWN").upper()
        attrs = item.get("attributes", item)
        tags_raw = attrs.get("tags", [])
        tags = sorted({str(t).lower() for t in tags_raw if isinstance(t, str)}) if isinstance(tags_raw, list) else []
        params = attrs.get("params", [])
        if not isinstance(params, list):
            params = []

        records.append({
            "entity_id": entity_id,
            "resource_path": str(attrs.get("path", "/")),
            "auth_required": bool(attrs.get("auth_required", True)),
            "params_count": len(params),
            "meta": {"source_version": source_version, "tags": tags},
        })

    output = {
        "schema_type": "harvested_api_inventory",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_records": len(records),
        "records": records,
    }

    output_path = Path(json_output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, sort_keys=True, ensure_ascii=False)
    except OSError as exc:
        raise ReportError(f"Cannot write output file: {exc}")

    Console.success(f"Transformer: {len(records)} records -> {json_output_path}")
    return len(records)


# ─────────────────────────────────────────────────────────────────────────────
#  Async Network Reconnaissance Functions
# ─────────────────────────────────────────────────────────────────────────────


async def async_dns_enumeration(domain: str, dns_client: DnsClient) -> DnsRecordSet:
    """DNS record enumeration using raw DNS protocol client."""
    records = DnsRecordSet()

    # A records: try socket.getaddrinfo first (fast), then raw DNS
    loop = asyncio.get_running_loop()

    def _getaddrinfo(host: str, family: int) -> List[str]:
        results = []
        try:
            infos = socket.getaddrinfo(host, None, family)
            for info in infos:
                ip = info[4][0]
                if ip not in results:
                    results.append(ip)
        except socket.gaierror:
            pass
        return results

    # A records via getaddrinfo
    a_records = await loop.run_in_executor(None, _getaddrinfo, domain, socket.AF_INET)
    records.a_records = sorted(set(a_records))

    # AAAA records via getaddrinfo
    aaaa_records = await loop.run_in_executor(None, _getaddrinfo, domain, socket.AF_INET6)
    records.aaaa_records = sorted(set(aaaa_records))

    # MX, NS, TXT, CNAME, SOA via raw DNS client
    record_types = [
        (DNS_TYPE_MX, "mx_records"),
        (DNS_TYPE_NS, "ns_records"),
        (DNS_TYPE_TXT, "txt_records"),
        (DNS_TYPE_CNAME, "cname_records"),
        (DNS_TYPE_SOA, "soa_records"),
    ]

    for qtype, attr_name in record_types:
        try:
            results = await loop.run_in_executor(None, dns_client.query, domain, qtype)
            if qtype == DNS_TYPE_SOA:
                # Filter out the structured markers
                clean_results = [r for r in results if not r.startswith("__soa_")]
                setattr(records, attr_name, sorted(set(clean_results)))
            else:
                setattr(records, attr_name, sorted(set(results)))
        except Exception as exc:
            Console.debug(f"DNS query failed for {domain} {TYPE_NAMES.get(qtype, qtype)}: {exc}")

    # Summary
    total = sum(len(getattr(records, attr)) for attr in
                ["a_records", "aaaa_records", "mx_records", "ns_records",
                 "txt_records", "cname_records", "soa_records"])
    if total > 0:
        Console.success(
            f"DNS: {domain} -> A:{len(records.a_records)} AAAA:{len(records.aaaa_records)} "
            f"MX:{len(records.mx_records)} NS:{len(records.ns_records)} "
            f"TXT:{len(records.txt_records)} CNAME:{len(records.cname_records)} "
            f"SOA:{len(records.soa_records)}"
        )
    else:
        Console.warning(f"DNS: {domain} -> no records found")

    return records


async def async_whois_lookup(domain: str, dns_client: DnsClient) -> WhoIsResult:
    """WHOIS-like info via SOA record."""
    loop = asyncio.get_running_loop()
    result = WhoIsResult(domain=domain)

    def _get_soa() -> WhoIsResult:
        res = WhoIsResult(domain=domain)
        try:
            soa_results = dns_client.query(domain, DNS_TYPE_SOA)
            for r in soa_results:
                if r.startswith("__soa_mname__="):
                    res.primary_nameserver = r.split("=", 1)[1]
                elif r.startswith("__soa_rname__="):
                    res.responsible_mail = r.split("=", 1)[1]
                elif r.startswith("__soa_serial__="):
                    res.serial_number = r.split("=", 1)[1]
        except Exception as exc:
            res.error = str(exc)
        return res

    result = await loop.run_in_executor(None, _get_soa)
    if result.error is None:
        Console.success(
            f"WHOIS: {domain} -> NS:{result.primary_nameserver} "
            f"Mail:{result.responsible_mail} Serial:{result.serial_number}"
        )
    else:
        Console.debug(f"WHOIS: {domain} -> {result.error}")
    return result


async def async_ip_geo(domain: str, timeout: int = 5) -> IpGeoResult:
    """Resolve IP and geo-lookup using free API."""
    loop = asyncio.get_running_loop()
    result = IpGeoResult(domain=domain)

    def _lookup() -> IpGeoResult:
        res = IpGeoResult(domain=domain)
        try:
            ip = socket.gethostbyname(domain)
            res.resolved_ip = ip

            # Use urllib to fetch geo data
            url = f"http://ip-api.com/json/{ip}"
            req = Request(url, headers={"User-Agent": f"ReconGuard/{__version__}"})
            with urlopen(req, timeout=timeout) as resp:
                if resp.getcode() == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") == "success":
                        res.country = data.get("country", "N/A")
                        res.city = data.get("city", "N/A")
                        res.isp = data.get("isp", "N/A")
                        res.asn = data.get("as", "N/A")
        except socket.gaierror:
            res.error = "DNS resolution failed"
        except URLError as exc:
            res.error = f"Geo API error: {exc.reason}"
        except socket.timeout:
            res.error = f"Geo API timeout ({timeout}s)"
        except Exception as exc:
            res.error = str(exc)
        return res

    result = await loop.run_in_executor(None, _lookup)
    if result.error is None:
        Console.success(f"IP/Geo: {domain} -> {result.resolved_ip} ({result.country}, {result.city}) [{result.asn}]")
    else:
        Console.debug(f"IP/Geo: {domain} -> {result.error}")
    return result


async def async_ssl_info(domain: str, timeout: int = 5) -> SslInfo:
    """SSL certificate retrieval using ssl module."""
    loop = asyncio.get_running_loop()
    result = SslInfo(domain=domain)

    def _ssl() -> SslInfo:
        res = SslInfo(domain=domain)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
                    if cert:
                        res.valid_from = cert.get("notBefore", "Unknown")
                        res.valid_until = cert.get("notAfter", "Unknown")

                        issuer = cert.get("issuer", ())
                        if issuer:
                            for rdn in issuer:
                                if isinstance(rdn, tuple):
                                    for key, value in rdn:
                                        if key == "organizationName":
                                            res.issuer = value
                                            break
                                elif isinstance(rdn, (list, tuple)) and len(rdn) == 2:
                                    if rdn[0] == "organizationName":
                                        res.issuer = rdn[1]
                                        break

                        subject = cert.get("subject", ())
                        if subject:
                            for rdn in subject:
                                if isinstance(rdn, tuple):
                                    for key, value in rdn:
                                        if key == "commonName":
                                            res.subject = value
                                            break
                                elif isinstance(rdn, (list, tuple)) and len(rdn) == 2:
                                    if rdn[0] == "commonName":
                                        res.subject = rdn[1]
                                        break

                        # Subject Alternative Names
                        san = cert.get("subjectAltName", [])
                        if san:
                            res.san = [name for typ, name in san if typ == "DNS"]

                        res.serial_number = str(cert.get("serialNumber", "Unknown")).upper()
        except ssl.SSLError as exc:
            res.error = f"SSL error: {exc}"
        except socket.timeout:
            res.error = f"SSL connection timeout ({timeout}s)"
        except ConnectionRefusedError:
            res.error = "Connection refused (port 443 not open)"
        except socket.gaierror:
            res.error = "DNS resolution failed"
        except Exception as exc:
            res.error = str(exc)
        return res

    result = await loop.run_in_executor(None, _ssl)
    if result.error is None:
        Console.success(
            f"SSL: {domain} -> expires {result.valid_until}, issuer: {result.issuer}, "
            f"subject: {result.subject}"
        )
    else:
        Console.debug(f"SSL: {domain} -> {result.error}")
    return result


async def async_port_scan(
    domain: str,
    ports: List[int],
    port_services: Dict[int, str],
    concurrency: int = 50,
    timeout: float = 1.5,
) -> PortScanResult:
    """Async TCP connect port scan with concurrency control."""
    result = PortScanResult(total_scanned=len(ports))
    sem = asyncio.Semaphore(concurrency)
    open_ports: Dict[int, str] = {}

    async def _check_port(port: int):
        async with sem:
            loop = asyncio.get_running_loop()

            def _connect() -> bool:
                try:
                    with socket.create_connection((domain, port), timeout=timeout):
                        return True
                except (ConnectionRefusedError, socket.timeout, OSError):
                    return False
                except Exception:
                    return False

            is_open = await loop.run_in_executor(None, _connect)
            if is_open:
                open_ports[port] = port_services.get(port, "Unknown")

    tasks = [_check_port(p) for p in ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    result.open_ports = dict(sorted(open_ports.items()))

    if result.open_ports:
        port_str = ", ".join(f"{p}/{s}" for p, s in sorted(result.open_ports.items()))
        Console.success(f"Ports: {domain} -> {len(result.open_ports)} open: {port_str}")
    else:
        Console.warning(f"Ports: {domain} -> no open ports (scanned {len(ports)})")

    return result


async def async_subdomain_discovery(
    domain: str,
    subdomains: List[str],
    concurrency: int = 30,
    timeout: float = 3.0,
) -> List[str]:
    """Resolve subdomains via DNS lookup with concurrency control."""
    sem = asyncio.Semaphore(concurrency)
    found: List[str] = []

    async def _try_sub(sub: str):
        async with sem:
            fqdn = f"{sub}.{domain}"
            loop = asyncio.get_running_loop()

            def _resolve() -> bool:
                try:
                    socket.getaddrinfo(fqdn, 80)
                    return True
                except socket.gaierror:
                    return False
                except OSError:
                    return False

            try:
                resolved = await asyncio.wait_for(
                    loop.run_in_executor(None, _resolve),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                resolved = False
            if resolved:
                found.append(fqdn)

    tasks = [_try_sub(s) for s in subdomains]
    await asyncio.gather(*tasks, return_exceptions=True)

    found = sorted(set(found))
    if found:
        preview = ", ".join(found[:5])
        if len(found) > 5:
            preview += f" ... +{len(found) - 5} more"
        Console.success(f"Subdomains: {domain} -> {len(found)} found ({preview})")
    else:
        Console.warning(f"Subdomains: {domain} -> none found (tried {len(subdomains)})")

    return found


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration Management
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "target_domains": [
        "example.com",
        "github.com"
    ],
    "target_endpoint": "robots.txt",
    "additional_endpoints": [
        "sitemap.xml",
        "sitemap_index.xml",
        ".env",
        "config.php",
        "phpinfo.php",
        "wp-admin/",
        "wp-json/",
        "api/",
        "health",
        "status",
        "crossdomain.xml",
        "security.txt"
    ],
    "http_timeout": 15,
    "max_concurrent_targets": 5,
    "port_scan_concurrency": 50,
    "port_scan_timeout": 1.5,
    "subdomain_concurrency": 30,
    "subdomain_timeout": 3.0,
    "dns_timeout": 5.0,
    "dns_retries": 2,
    "common_ports": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
        5985, 5986, 6379, 8080, 8443, 9090, 27017
    ],
    "port_services": {
        "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS",
        "80": "HTTP", "110": "POP3", "111": "RPC", "135": "RPC", "139": "NetBIOS",
        "143": "IMAP", "443": "HTTPS", "445": "SMB", "993": "IMAPS", "995": "POP3S",
        "1433": "MSSQL", "1521": "Oracle", "2049": "NFS", "3306": "MySQL",
        "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC", "5985": "WinRM-HTTP",
        "5986": "WinRM-HTTPS", "6379": "Redis", "8080": "HTTP-Proxy",
        "8443": "HTTPS-Alt", "9090": "HTTP-Alt", "27017": "MongoDB"
    },
    "common_subdomains": [
        "www", "mail", "admin", "api", "dev", "test", "beta", "cdn",
        "app", "blog", "shop", "portal", "secure", "vpn", "remote",
        "git", "jenkins", "grafana", "kibana", "dashboard",
        "stage", "prod", "staging", "demo", "sandbox",
        "webmail", "owa", "exchange", "autodiscover",
        "s3", "bucket", "storage", "assets", "static",
        "login", "auth", "sso", "oauth", "identity",
        "config", "setup", "install",
        "intranet", "internal", "corp", "hr",
        "gateway", "proxy", "lb", "loadbalancer",
        "backup", "db", "database", "mysql", "redis",
        "monitor", "status", "support", "help", "docs", "wiki", "staff",
        "ims", "ggsn", "sgw", "pgw", "hss", "mme", "ocs", "ofcs",
        "smsc", "hlr", "charging", "billing", "radius", "dhcp",
        "dns1", "dns2", "ntp", "sip", "rtp", "mgw",
        "crm", "erp", "bi", "analytics", "reports",
        "ussd", "ivr", "callcenter", "csc",
        "ems", "nms", "oss", "element"
    ],
    "custom_regex_patterns": None
}


def load_config(config_path: str) -> dict:
    """Load and validate configuration from JSON file."""
    path = Path(config_path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in config file: {exc}")
    except OSError as exc:
        raise ConfigError(f"Cannot read config file: {exc}")

    # Merge with defaults
    merged = DEFAULT_CONFIG.copy()
    merged.update(config)

    # If custom_regex_patterns is null, use defaults
    if merged.get("custom_regex_patterns") is None:
        merged["custom_regex_patterns"] = dict(DEFAULT_REGEX_PATTERNS)

    # Validate
    if not merged.get("target_domains"):
        raise ConfigError("No target_domains specified in config")

    if not isinstance(merged.get("target_domains"), list):
        raise ConfigError("target_domains must be a list")

    # Validate ports
    ports = merged.get("common_ports", [])
    merged["common_ports"] = validate_ports(ports)

    # Validate port_services keys
    port_services = {}
    raw_services = merged.get("port_services", {})
    for k, v in raw_services.items():
        try:
            port_services[int(k)] = v
        except (ValueError, TypeError):
            pass
    merged["port_services"] = port_services

    # Validate timeout values
    merged["http_timeout"] = max(1, min(120, int(merged.get("http_timeout", 15))))
    merged["max_concurrent_targets"] = max(1, min(50, int(merged.get("max_concurrent_targets", 5))))
    merged["port_scan_concurrency"] = max(1, min(500, int(merged.get("port_scan_concurrency", 50))))
    merged["subdomain_concurrency"] = max(1, min(200, int(merged.get("subdomain_concurrency", 30))))

    # Validate regex patterns
    regex_patterns = merged.get("custom_regex_patterns", {})
    if regex_patterns:
        validated_patterns = {}
        for name, pattern in regex_patterns.items():
            try:
                re.compile(pattern)
                validated_patterns[name] = pattern
            except re.error as exc:
                Console.warning(f"Invalid regex pattern '{name}': {exc}")
        merged["custom_regex_patterns"] = validated_patterns

    return merged


def init_config(output_path: str = "config.json") -> str:
    """Write a sample config file."""
    path = Path(output_path)
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4, ensure_ascii=False)
        Console.success(f"Sample config written to {output_path}")
        return output_path
    except OSError as exc:
        raise ConfigError(f"Cannot write config file: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Pipeline Orchestration
# ─────────────────────────────────────────────────────────────────────────────


async def run_pipeline(config: dict, output_path: str = "report.json", modules: Optional[List[str]] = None) -> dict:
    """Run the full recon pipeline."""
    start_time = time.time()

    # Extract configuration
    target_domains: List[str] = config.get("target_domains", [])
    target_endpoint: str = config.get("target_endpoint", "robots.txt")
    additional_endpoints: List[str] = config.get("additional_endpoints", [])
    http_timeout: int = config.get("http_timeout", 15)
    common_ports: List[int] = config.get("common_ports", [80, 443])
    port_services: Dict[int, str] = config.get("port_services", {})
    common_subdomains: List[str] = config.get("common_subdomains", ["www"])
    regex_patterns: Dict[str, str] = config.get("custom_regex_patterns", DEFAULT_REGEX_PATTERNS)
    max_concurrent: int = config.get("max_concurrent_targets", 5)
    port_concurrency: int = config.get("port_scan_concurrency", 50)
    port_timeout: float = config.get("port_scan_timeout", 1.5)
    sub_concurrency: int = config.get("subdomain_concurrency", 30)
    sub_timeout: float = config.get("subdomain_timeout", 3.0)
    dns_timeout: float = config.get("dns_timeout", 5.0)
    dns_retries: int = config.get("dns_retries", 2)

    # All modules by default
    if modules is None:
        modules = ["dns", "whois", "http", "geo", "ssl", "ports", "subdomains"]

    # Step 1: Clean domains
    cleaned_domains = task_1_domain_pipeline(target_domains)
    if not cleaned_domains:
        raise ValidationError("No valid domains found in configuration")

    Console.info(f"Targets: {', '.join(cleaned_domains)}")
    Console.info(f"Modules: {', '.join(modules)}")
    print()

    # DNS client instance
    dns_client = DnsClient(timeout=dns_timeout, retries=dns_retries)

    # Step 2: Concurrent per-target recon
    sem = asyncio.Semaphore(max_concurrent)

    async def recon_one(domain: str) -> Dict[str, Any]:
        async with sem:
            Console.separator(f"Scanning: {domain}")

            http_result = None
            dns_result = None
            whois_result = None
            geo_result = None
            ssl_result = None
            port_result = None
            sub_result = None
            security_headers = None

            # Run tasks concurrently
            tasks = []

            if "http" in modules:
                async def _http():
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(
                        None, task_2_http_recon, domain,
                        target_endpoint, additional_endpoints, http_timeout
                    )
                tasks.append(("http", _http()))

            if "dns" in modules:
                tasks.append(("dns", async_dns_enumeration(domain, dns_client)))

            if "whois" in modules:
                tasks.append(("whois", async_whois_lookup(domain, dns_client)))

            if "geo" in modules:
                tasks.append(("geo", async_ip_geo(domain)))

            if "ssl" in modules:
                tasks.append(("ssl", async_ssl_info(domain)))

            if "ports" in modules:
                tasks.append(("ports", async_port_scan(
                    domain, common_ports, port_services,
                    concurrency=port_concurrency, timeout=port_timeout
                )))

            if "subdomains" in modules:
                tasks.append(("subdomains", async_subdomain_discovery(
                    domain, common_subdomains,
                    concurrency=sub_concurrency, timeout=sub_timeout
                )))

            # Execute all tasks
            for name, task in tasks:
                try:
                    result = await task
                    if name == "http":
                        http_result = result
                        if result and "headers" in result:
                            security_headers = _check_security_headers(result.get("headers", {}))
                    elif name == "dns":
                        dns_result = asdict(result) if result else None
                    elif name == "whois":
                        whois_result = asdict(result) if result else None
                    elif name == "geo":
                        geo_result = asdict(result) if result else None
                    elif name == "ssl":
                        ssl_result = asdict(result) if result else None
                    elif name == "ports":
                        port_result = asdict(result) if result else None
                    elif name == "subdomains":
                        sub_result = result
                except Exception as exc:
                    Console.error(f"Module '{name}' failed for {domain}: {exc}")

            return {
                "domain": domain,
                "http": http_result,
                "dns": dns_result,
                "whois": whois_result,
                "geo": geo_result,
                "ssl": ssl_result,
                "ports": port_result,
                "subdomains": sub_result,
                "security_headers": security_headers,
            }

    all_results = await asyncio.gather(*[recon_one(d) for d in cleaned_domains])

    # Step 3: Regex extraction across all HTTP content
    Console.separator("Regex Extraction")
    all_payloads = " ".join(
        str(r.get("http", {}).get("content_preview", ""))
        for r in all_results if r.get("http")
    )
    regex_report = task_3_regex_extraction(all_payloads, regex_patterns)

    # Build final report
    elapsed = time.time() - start_time
    report: Dict[str, Any] = {
        "pipeline_metadata": {
            "tool_name": __tool_name__,
            "tool_version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_system": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
            "total_targets": len(cleaned_domains),
            "modules_run": modules,
            "elapsed_seconds": round(elapsed, 2),
        },
        "targets": all_results,
        "pattern_extraction": regex_report,
    }

    # Write JSON report
    report_path = Path(output_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        Console.success(f"JSON report saved to: {output_path}")
    except OSError as exc:
        raise ReportError(f"Cannot write report file: {exc}")

    # Write Markdown report
    md_path = Path(output_path).with_suffix(".md")
    try:
        _write_markdown_report(report, str(md_path))
        Console.success(f"Markdown report saved to: {md_path}")
    except Exception as exc:
        Console.warning(f"Could not write Markdown report: {exc}")

    # Print summary
    print()
    Console.separator("Pipeline Summary")
    Console.info(f"Targets scanned: {len(cleaned_domains)}")
    Console.info(f"Time elapsed: {elapsed:.2f}s")
    total_findings = sum(len(v) for v in regex_report.values())
    Console.info(f"Regex findings: {total_findings}")
    total_open_ports = sum(
        len(r.get("ports", {}).get("open_ports", {}))
        for r in all_results if r.get("ports")
    )
    Console.info(f"Total open ports: {total_open_ports}")
    total_subdomains = sum(
        len(r.get("subdomains", []))
        for r in all_results if r.get("subdomains")
    )
    Console.info(f"Total subdomains found: {total_subdomains}")

    print()
    Console.success("Pipeline complete!")

    return report


def _write_markdown_report(report: dict, output_path: str):
    """Write a human-readable Markdown report."""
    lines = []
    meta = report.get("pipeline_metadata", {})
    targets = report.get("targets", [])
    patterns = report.get("pattern_extraction", {})

    lines.append(f"# {__tool_name__} — Security Reconnaissance Report\n")
    lines.append(f"**Generated:** {meta.get('timestamp', 'N/A')}")
    lines.append(f"**Tool Version:** {meta.get('tool_version', 'N/A')}")
    lines.append(f"**System:** {meta.get('execution_system', 'N/A')}")
    lines.append(f"**Python:** {meta.get('python_version', 'N/A')}")
    lines.append(f"**Duration:** {meta.get('elapsed_seconds', 'N/A')}s")
    lines.append(f"**Targets:** {meta.get('total_targets', 0)}")
    lines.append("")

    for target in targets:
        domain = target.get("domain", "Unknown")
        lines.append(f"## Target: {domain}\n")

        # HTTP
        http = target.get("http")
        if http:
            lines.append("### HTTP Reconnaissance\n")
            lines.append(f"- **URL:** {http.get('url', 'N/A')}")
            lines.append(f"- **Status Code:** {http.get('status_code', 'N/A')}")
            lines.append(f"- **Content Length:** {http.get('content_length', 0)} bytes")
            techs = http.get("technologies", [])
            lines.append(f"- **Technologies:** {', '.join(techs) if techs else 'None detected'}")
            if http.get("cms"):
                lines.append(f"- **CMS:** {http['cms']}")
            lines.append("")

            # Security Headers
            sec = target.get("security_headers")
            if sec:
                lines.append("### Security Headers\n")
                lines.append(f"- **Security Score:** {sec.get('security_score', 'N/A')}")
                present = sec.get("present", {})
                missing = sec.get("missing", [])
                if present:
                    lines.append("- **Present:**")
                    for name, value in present.items():
                        lines.append(f"  - {name}: `{value[:80]}...`" if len(value) > 80 else f"  - {name}: `{value}`")
                if missing:
                    lines.append(f"- **Missing:** {', '.join(missing)}")
                lines.append("")

        # DNS
        dns = target.get("dns")
        if dns:
            lines.append("### DNS Records\n")
            for rtype in ["a_records", "aaaa_records", "mx_records", "ns_records", "txt_records", "cname_records", "soa_records"]:
                records = dns.get(rtype, [])
                if records:
                    display = rtype.replace("_", " ").upper()
                    lines.append(f"- **{display}:** {', '.join(records)}")
            lines.append("")

        # WHOIS
        whois = target.get("whois")
        if whois:
            lines.append("### WHOIS (SOA)\n")
            lines.append(f"- **Primary Nameserver:** {whois.get('primary_nameserver', 'N/A')}")
            lines.append(f"- **Responsible Mail:** {whois.get('responsible_mail', 'N/A')}")
            lines.append(f"- **Serial Number:** {whois.get('serial_number', 'N/A')}")
            lines.append("")

        # IP/Geo
        geo = target.get("geo")
        if geo:
            lines.append("### IP Geolocation\n")
            lines.append(f"- **Resolved IP:** {geo.get('resolved_ip', 'N/A')}")
            lines.append(f"- **Country:** {geo.get('country', 'N/A')}")
            lines.append(f"- **City:** {geo.get('city', 'N/A')}")
            lines.append(f"- **ISP:** {geo.get('isp', 'N/A')}")
            lines.append(f"- **ASN:** {geo.get('asn', 'N/A')}")
            lines.append("")

        # SSL
        ssl_info = target.get("ssl")
        if ssl_info:
            lines.append("### SSL Certificate\n")
            lines.append(f"- **Subject:** {ssl_info.get('subject', 'N/A')}")
            lines.append(f"- **Issuer:** {ssl_info.get('issuer', 'N/A')}")
            lines.append(f"- **Valid From:** {ssl_info.get('valid_from', 'N/A')}")
            lines.append(f"- **Valid Until:** {ssl_info.get('valid_until', 'N/A')}")
            san = ssl_info.get("san", [])
            if san:
                lines.append(f"- **SAN:** {', '.join(san[:5])}{'...' if len(san) > 5 else ''}")
            lines.append("")

        # Ports
        ports = target.get("ports")
        if ports:
            lines.append("### Port Scan Results\n")
            open_ports = ports.get("open_ports", {})
            total = ports.get("total_scanned", 0)
            lines.append(f"- **Ports Scanned:** {total}")
            if open_ports:
                lines.append(f"- **Open Ports:** {len(open_ports)}")
                for port, svc in sorted(open_ports.items()):
                    lines.append(f"  - {port}/TCP — {svc}")
            else:
                lines.append("- **Open Ports:** None")
            lines.append("")

        # Subdomains
        subs = target.get("subdomains")
        if subs:
            lines.append("### Subdomain Discovery\n")
            lines.append(f"- **Found:** {len(subs)} subdomain(s)")
            for s in subs[:20]:
                lines.append(f"  - {s}")
            if len(subs) > 20:
                lines.append(f"  - ... and {len(subs) - 20} more")
            lines.append("")

        lines.append("---\n")

    # Regex findings
    if patterns:
        lines.append("## Pattern Extraction Summary\n")
        for name, matches in patterns.items():
            if matches:
                lines.append(f"### {name} ({len(matches)} matches)\n")
                for m in matches[:10]:
                    lines.append(f"- `{m}`")
                if len(matches) > 10:
                    lines.append(f"- ... and {len(matches) - 10} more")
                lines.append("")

    lines.append("---")
    lines.append(f"\n*Report generated by {__tool_name__} v{__version__} — Pure Python Standard Library*")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
#  CLI Interface
# ─────────────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog=__tool_name__,
        description=f"{__tool_name__} v{__version__} — Pure Python Security Reconnaissance Tool",
        epilog=(
            "WARNING: This tool is for authorized security testing ONLY.\n"
            "Unauthorized scanning is illegal and unethical.\n\n"
            f"Author: {__author__}\n"
            f"License: MIT"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global options (work both before and after subcommand)
    parser.add_argument(
        "--version", action="version",
        version=f"{__tool_name__} {__version__}\nAuthor: {__author__}\nPure Python — Standard Library Only"
    )
    parser.add_argument(
        "--config", metavar="PATH", default="config.json",
        help="Path to configuration JSON file (default: config.json)"
    )
    parser.add_argument(
        "--log-level", metavar="LEVEL", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level (default: INFO)"
    )
    parser.add_argument(
        "--timeout", type=int, default=None,
        metavar="SECONDS",
        help="Override HTTP timeout in seconds"
    )

    # Common options shared across subcommands (via parent parser)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", metavar="PATH", default="config.json",
        help="Path to configuration JSON file (default: config.json)"
    )
    common.add_argument(
        "--log-level", metavar="LEVEL", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level (default: INFO)"
    )
    common.add_argument(
        "--timeout", type=int, default=None,
        metavar="SECONDS",
        help="Override HTTP timeout in seconds"
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan - full pipeline
    scan_parser = subparsers.add_parser(
        "scan", parents=[common],
        help="Run full reconnaissance pipeline"
    )
    scan_parser.add_argument(
        "--modules", nargs="*", default=None,
        choices=["dns", "whois", "http", "geo", "ssl", "ports", "subdomains"],
        help="Specific modules to run (default: all)"
    )
    scan_parser.add_argument(
        "--output", "-o", metavar="PATH", default="report.json",
        help="Output report file path (default: report.json)"
    )

    # dns - DNS only
    dns_parser = subparsers.add_parser(
        "dns", parents=[common],
        help="DNS enumeration only"
    )
    dns_parser.add_argument(
        "domain", nargs="?", default=None,
        help="Target domain (overrides config)"
    )

    # http - HTTP only
    http_parser = subparsers.add_parser(
        "http", parents=[common],
        help="HTTP reconnaissance only"
    )
    http_parser.add_argument(
        "domain", nargs="?", default=None,
        help="Target domain (overrides config)"
    )
    http_parser.add_argument(
        "--endpoint", default="robots.txt",
        help="Endpoint to check (default: robots.txt)"
    )

    # ports - port scan only
    ports_parser = subparsers.add_parser(
        "ports", parents=[common],
        help="Port scan only"
    )
    ports_parser.add_argument(
        "domain", nargs="?", default=None,
        help="Target domain (overrides config)"
    )

    # subdomains - subdomain discovery only
    sub_parser = subparsers.add_parser(
        "subdomains", parents=[common],
        help="Subdomain discovery only"
    )
    sub_parser.add_argument(
        "domain", nargs="?", default=None,
        help="Target domain (overrides config)"
    )

    # extract - regex extraction
    extract_parser = subparsers.add_parser(
        "extract", parents=[common],
        help="Extract secrets/patterns from a file"
    )
    extract_parser.add_argument(
        "input", help="Input file path"
    )
    extract_parser.add_argument(
        "--output", "-o", default=None,
        help="Output JSON file (default: stdout)"
    )

    # transform - JSON schema transformer
    transform_parser = subparsers.add_parser(
        "transform", parents=[common],
        help="Transform API inventory JSON"
    )
    transform_parser.add_argument(
        "input", help="Input JSON file path"
    )
    transform_parser.add_argument(
        "output", help="Output JSON file path"
    )

    # init-config - write sample config
    init_parser = subparsers.add_parser(
        "init-config", parents=[common],
        help="Write a sample configuration file"
    )
    init_parser.add_argument(
        "--path", default="config.json",
        help="Output path (default: config.json)"
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  Command Handlers
# ─────────────────────────────────────────────────────────────────────────────


async def cmd_scan(args) -> int:
    """Handle the scan command."""
    config = load_config(args.config)
    if args.timeout:
        config["http_timeout"] = args.timeout

    modules = args.modules
    await run_pipeline(config, output_path=args.output, modules=modules)
    return 0


async def cmd_dns(args) -> int:
    """Handle the dns command."""
    domain = clean_domain(args.domain) if args.domain else None
    if not domain:
        # Try from config
        config = load_config(args.config)
        domains = task_1_domain_pipeline(config.get("target_domains", []))
        if not domains:
            Console.error("No valid domain provided")
            return 1
        domain = domains[0]

    dns_client = DnsClient(timeout=5.0, retries=2)
    Console.separator(f"DNS Enumeration: {domain}")
    records = await async_dns_enumeration(domain, dns_client)

    result = asdict(records)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


async def cmd_http(args) -> int:
    """Handle the http command."""
    domain = clean_domain(args.domain) if args.domain else None
    if not domain:
        config = load_config(args.config)
        domains = task_1_domain_pipeline(config.get("target_domains", []))
        if not domains:
            Console.error("No valid domain provided")
            return 1
        domain = domains[0]

    timeout = args.timeout or 15
    Console.separator(f"HTTP Reconnaissance: {domain}")
    result = task_2_http_recon(domain, args.endpoint, timeout=timeout)
    if result:
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return 0
    else:
        Console.error("HTTP recon failed")
        return 1


async def cmd_ports(args) -> int:
    """Handle the ports command."""
    domain = clean_domain(args.domain) if args.domain else None
    if not domain:
        config = load_config(args.config)
        domains = task_1_domain_pipeline(config.get("target_domains", []))
        if not domains:
            Console.error("No valid domain provided")
            return 1
        domain = domains[0]

    config = load_config(args.config)
    ports = config.get("common_ports", [80, 443])
    port_services = config.get("port_services", {})
    concurrency = config.get("port_scan_concurrency", 50)
    port_timeout = config.get("port_scan_timeout", 1.5)

    Console.separator(f"Port Scan: {domain}")
    result = await async_port_scan(domain, ports, port_services,
                                    concurrency=concurrency, timeout=port_timeout)
    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))
    return 0


async def cmd_subdomains(args) -> int:
    """Handle the subdomains command."""
    domain = clean_domain(args.domain) if args.domain else None
    if not domain:
        config = load_config(args.config)
        domains = task_1_domain_pipeline(config.get("target_domains", []))
        if not domains:
            Console.error("No valid domain provided")
            return 1
        domain = domains[0]

    config = load_config(args.config)
    subdomains = config.get("common_subdomains", ["www"])
    concurrency = config.get("subdomain_concurrency", 30)
    sub_timeout = config.get("subdomain_timeout", 3.0)

    Console.separator(f"Subdomain Discovery: {domain}")
    result = await async_subdomain_discovery(domain, subdomains,
                                              concurrency=concurrency, timeout=sub_timeout)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_extract(args) -> int:
    """Handle the extract command."""
    input_path = Path(args.input)
    if not input_path.is_file():
        Console.error(f"Input file not found: {args.input}")
        return 1

    try:
        with input_path.open("r", encoding="utf-8", errors="replace") as f:
            corpus = f.read()
    except OSError as exc:
        Console.error(f"Cannot read file: {exc}")
        return 1

    Console.separator(f"Pattern Extraction: {args.input}")
    results = task_3_regex_extraction(corpus, DEFAULT_REGEX_PATTERNS)

    output = json.dumps(results, indent=2, ensure_ascii=False)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            Console.success(f"Results saved to: {args.output}")
        except OSError as exc:
            Console.error(f"Cannot write output: {exc}")
            return 1
    else:
        print(output)
    return 0


def cmd_transform(args) -> int:
    """Handle the transform command."""
    try:
        count = task_4_json_transformer(args.input, args.output)
        Console.success(f"Transformed {count} records")
        return 0
    except (ValidationError, ReportError) as exc:
        Console.error(str(exc))
        return 1


def cmd_init_config(args) -> int:
    """Handle the init-config command."""
    try:
        path = init_config(args.path)
        Console.success(f"Config written to: {path}")
        Console.info("Edit the file to set your targets and run: python recon_guard.py scan")
        return 0
    except ConfigError as exc:
        Console.error(str(exc))
        return 1


# ─────────────────────────────────────────────────────────────────────────────
#  Main Entry Point
# ─────────────────────────────────────────────────────────────────────────────


async def _async_main(args) -> int:
    """Async main entry point."""
    command = args.command

    if command == "scan":
        return await cmd_scan(args)
    elif command == "dns":
        return await cmd_dns(args)
    elif command == "http":
        return await cmd_http(args)
    elif command == "ports":
        return await cmd_ports(args)
    elif command == "subdomains":
        return await cmd_subdomains(args)
    elif command == "extract":
        return cmd_extract(args)
    elif command == "transform":
        return cmd_transform(args)
    elif command == "init-config":
        return cmd_init_config(args)
    else:
        Console.error(f"Unknown command: {command}")
        return 1


def main():
    """Main entry point with comprehensive error handling."""
    parser = build_parser()
    args = parser.parse_args()

    # If no command given, show help
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Initialize console/logger
    log_level = getattr(args, "log_level", "INFO")
    Console.init_logger(log_level)

    # Show banner for scan and recon commands
    if args.command in ("scan", "dns", "http", "ports", "subdomains"):
        Console.banner()

    try:
        exit_code = asyncio.run(_async_main(args))
        sys.exit(exit_code)
    except ConfigError as exc:
        Console.error(f"Configuration error: {exc}")
        sys.exit(2)
    except ValidationError as exc:
        Console.error(f"Validation error: {exc}")
        sys.exit(3)
    except NetworkError as exc:
        Console.error(f"Network error: {exc}")
        sys.exit(4)
    except PermissionError as exc:
        Console.error(f"Permission error: {exc}")
        sys.exit(5)
    except ReportError as exc:
        Console.error(f"Report error: {exc}")
        sys.exit(6)
    except KeyboardInterrupt:
        Console.warning("\nOperation cancelled by user (Ctrl+C)")
        sys.exit(130)
    except Exception as exc:
        Console.error(f"Unexpected error: {exc}")
        if log_level == "DEBUG":
            import traceback
            traceback.print_exc()
        else:
            Console.info("Run with --log-level DEBUG for more details")
        sys.exit(1)


if __name__ == "__main__":
    main()
