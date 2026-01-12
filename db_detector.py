#!/usr/bin/env python3
"""
Database Detector - Fast, safe database identification from IP lists
Author: Calyie
License: MIT
Version: 1.0.0

"""

import socket
import struct
import re
import csv
import argparse
import concurrent.futures
import time
import base64
import ssl
import threading
from typing import List, Set, Optional, Tuple, Dict, Iterator, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import sys


VERSION = "1.0.0"

BANNER = r"""
    ____  ____
   / __ \/ __ )     Database Detector v{version}
  / / / / __  |     Fast Database Identification
 / /_/ / /_/ /      Author -> Calyie
/_____/_____/       https://github.com/Calyie/database-detector

 Supported: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle,
            Cassandra, Elasticsearch, CouchDB, InfluxDB, Neo4j
"""

# Expanded well-known/alt ports
DB_PORTS: Dict[int, str] = {
    # MySQL
    3306: "MySQL", 3307: "MySQL", 13306: "MySQL", 23306: "MySQL", 33060: "MySQL", 33061: "MySQL", 33062: "MySQL",
    # PostgreSQL
    5432: "PostgreSQL", 5433: "PostgreSQL", 15432: "PostgreSQL", 6432: "PostgreSQL",
    # MongoDB
    27017: "MongoDB", 27018: "MongoDB", 27019: "MongoDB", 28017: "MongoDB",
    # Redis
    6379: "Redis", 6380: "Redis", 16379: "Redis",
    # MSSQL
    1433: "MSSQL", 1434: "MSSQL", 11433: "MSSQL",
    # Oracle
    1521: "Oracle", 1522: "Oracle", 2483: "Oracle", 2484: "Oracle",
    # Cassandra
    9042: "Cassandra", 9142: "Cassandra", 9160: "Cassandra", 7000: "Cassandra", 7001: "Cassandra",  # internode ports (common to be silent to client probes)
    # Elasticsearch
    9200: "Elasticsearch", 9201: "Elasticsearch", 9202: "Elasticsearch", 9203: "Elasticsearch", 9204: "Elasticsearch",
    # CouchDB
    5984: "CouchDB", 6984: "CouchDB",
    # InfluxDB
    8086: "InfluxDB", 8088: "InfluxDB",
    # Neo4j
    7474: "Neo4j", 7473: "Neo4j", 7687: "Neo4j",
}

CANONICAL_DB_PORTS: Set[int] = set(DB_PORTS.keys())

# Cassandra port semantics
CASSANDRA_CQL_PORTS: Set[int] = {9042, 9142}       # native protocol client ports
CASSANDRA_INTERNODE_PORTS: Set[int] = {7000, 7001} # cluster internode (often TLS/mTLS and peer-restricted)

LARGE_INPUT_THRESHOLD = 2000

DEFAULT_EXCLUDE_PORTS: Set[int] = {
    20, 21, 22, 23, 25, 110, 143, 53, 111,
    135, 137, 138, 139, 445, 389, 636, 623, 873,
    3389, 5900, 5985, 5986, 161, 162,
}

TOP_PORTS: List[int] = list(range(1, 1025)) + [
    *sorted(CANONICAL_DB_PORTS),
    1080, 1443, 2000, 2080, 2082, 2083, 2086, 2087, 2095, 2096,
    3000, 3001, 3002, 3003, 4000, 4040, 5000, 5001, 5050, 5601,
    7070, 7443, 7777, 8000, 8001, 8008, 8010, 8080, 8081, 8082, 8083, 8088,
    8090, 8100, 8181, 8200, 8222, 8300, 8333, 8443, 8500, 8545, 8600, 8761,
    8888, 9000, 9001, 9043, 9050, 9080, 9090, 9091, 9092, 9100, 9400, 9443,
    10000, 10001, 10250, 10255, 11211, 15672, 15692,
    2379, 2380,
]


@dataclass
class DatabaseDetection:
    ip: str
    port: int
    db_type: str
    confidence: float
    verified: bool
    reason: str


class IPValidator:
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    @classmethod
    def extract_ips(cls, text: str) -> Set[str]:
        potential_ips = cls.IPV4_PATTERN.findall(text)
        return {ip for ip in potential_ips if cls.is_valid_ip(ip)}

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False


def read_ips_from_file(filepath: str) -> Set[str]:
    path = Path(filepath)
    if not path.exists():
        print(f"[!] Error: File not found: {filepath}")
        sys.exit(1)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        ips = IPValidator.extract_ips(content)
        if not ips:
            print(f"[!] Error: No valid IPv4 addresses found in {filepath}")
            sys.exit(1)
        return ips
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)


def parse_portspec(spec: str) -> Set[int]:
    ports: Set[int] = set()
    if not spec:
        return ports
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            try:
                start = int(a.strip())
                end = int(b.strip())
                if start > end:
                    start, end = end, start
                for p in range(max(1, start), min(65535, end) + 1):
                    ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return ports


def build_top_ports_list(top_ports_count: int) -> List[int]:
    merged = list(dict.fromkeys(TOP_PORTS + sorted(CANONICAL_DB_PORTS)))
    if top_ports_count > 0:
        base = merged[: min(top_ports_count, len(merged))]
    else:
        base = merged
    return list(dict.fromkeys(base + sorted(CANONICAL_DB_PORTS)))


class DatabaseDetector:
    def __init__(
        self,
        connect_timeout: float,
        probe_timeout: float,
        greeting_wait: float,
        wakeup_enabled: bool,
        debug: bool = False,
        debug_full: bool = False,
    ):
        self.connect_timeout = float(connect_timeout)
        self.probe_timeout = float(probe_timeout)
        self.greeting_wait = float(greeting_wait)
        self.wakeup_enabled = bool(wakeup_enabled)
        self.debug = debug
        self.debug_full = debug_full

    # ---------------- Debug ----------------
    def _dbg(self, msg: str):
        if self.debug:
            print(msg, file=sys.stderr)

    def _dump_bytes(self, tag: str, b: bytes):
        if not self.debug:
            return
        if not b:
            self._dbg(f"[debug] {tag}: <empty>")
            return
        shown = b if self.debug_full else b[:4096]
        self._dbg(f"[debug] {tag}: bytes={len(b)} shown={len(shown)}")
        self._dbg(f"[debug] {tag}: hex={shown.hex()}")
        self._dbg(f"[debug] {tag}: b64={base64.b64encode(shown).decode('ascii')}")

    # --------------- Confidence / reason ---------------
    def _verified(self, conf: float) -> bool:
        return conf >= 0.95

    def _tier(self, conf: float) -> str:
        # More user-friendly tiers
        if conf >= 1.00:
            return "definitive"
        if conf >= 0.95:
            return "strong"
        if conf >= 0.80:
            return "likely"
        if conf >= 0.55:
            return "possible"
        return "open-only"

    def _reason(self, conf: float, sentence: str, evidence: str) -> str:
        # Always: "<tier>: <sentence> (evidence: ...)"
        return f"{self._tier(conf)}: {sentence} (evidence: {evidence})"

    # --------------- Socket helpers ---------------
    def _connect_ex(self, ip: str, port: int, timeout: float) -> Tuple[Optional[socket.socket], int]:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            code = s.connect_ex((ip, port))
            if code != 0:
                try:
                    s.close()
                except Exception:
                    pass
                return None, code
            return s, 0
        except Exception as e:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            self._dbg(f"[debug] connect exception {ip}:{port} -> {type(e).__name__}: {e}")
            return None, -1

    def _recv_exact(self, sock: socket.socket, n: int, total_timeout: float) -> bytes:
        buf = bytearray()
        end = time.time() + total_timeout
        while len(buf) < n:
            remaining = end - time.time()
            if remaining <= 0:
                return b""
            sock.settimeout(min(1.0, remaining))
            try:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    return b""
                buf.extend(chunk)
            except socket.timeout:
                continue
            except Exception:
                return b""
        return bytes(buf)

    def _recv_any(self, sock: socket.socket, total_timeout: float, max_bytes: int) -> bytes:
        data = bytearray()
        end = time.time() + total_timeout
        while time.time() < end and len(data) < max_bytes:
            remaining = end - time.time()
            if remaining <= 0:
                break
            sock.settimeout(min(1.0, remaining))
            try:
                chunk = sock.recv(min(4096, max_bytes - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            except socket.timeout:
                continue
            except Exception:
                break
        return bytes(data)

    def _peek_status(self, sock: socket.socket, wait: float) -> str:
        """
        Returns one of:
          - "data"   : data is available immediately
          - "closed" : peer closed connection quickly
          - "silent" : no data observed within wait
        """
        try:
            sock.settimeout(max(0.05, wait))
            try:
                b = sock.recv(1, socket.MSG_PEEK)
            except (AttributeError, OSError):
                # MSG_PEEK not supported in some environments; fallback:
                b = sock.recv(1)
                if b:
                    # we consumed 1 byte; can't put it back, so treat as data
                    return "data"
                return "closed"

            if b == b"":
                return "closed"
            return "data"
        except socket.timeout:
            return "silent"
        except Exception:
            return "silent"

    def _wrap_tls(self, s: socket.socket, server_name: str) -> Optional[ssl.SSLSocket]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(s, server_hostname=server_name)
            tls.settimeout(max(self.probe_timeout, 6.0))
            return tls
        except Exception as e:
            self._dbg(f"[debug] tls wrap failed -> {type(e).__name__}: {e}")
            return None

    # --------------- Protocol probe builders ---------------
    def _postgres_ssl_request(self) -> bytes:
        return struct.pack("!II", 8, 80877103)

    def _mssql_prelogin_v1(self) -> bytes:
        table_len = 11
        version_off = table_len
        version_len = 6
        enc_off = table_len + version_len
        enc_len = 1
        options = (
            b"\x00" + struct.pack("!HH", version_off, version_len) +
            b"\x01" + struct.pack("!HH", enc_off, enc_len) +
            b"\xFF"
        )
        payload = options + (b"\x00" * 6) + b"\x00"
        length = 8 + len(payload)
        header = b"\x12\x01" + struct.pack("!H", length) + b"\x00\x00" + b"\x00" + b"\x00"
        return header + payload

    def _mssql_prelogin_v2(self) -> bytes:
        options = (
            b"\x01" + struct.pack("!HH", 0x0016, 0x0001) +
            b"\x00" + struct.pack("!HH", 0x0017, 0x0006) +
            b"\xFF"
        )
        payload = options + b"\x00" + (b"\x00" * 6)
        length = 8 + len(payload)
        header = b"\x12\x01" + struct.pack("!H", length) + b"\x00\x00" + b"\x00" + b"\x00"
        return header + payload

    def _cassandra_options(self, v: int) -> bytes:
        return bytes([v, 0x00, 0x00, 0x00, 0x05]) + b"\x00\x00\x00\x00"

    def _neo4j_bolt_handshake(self) -> bytes:
        return (
            b"\x60\x60\xB0\x17" +
            b"\x00\x00\x00\x05" +
            b"\x00\x00\x00\x04" +
            b"\x00\x00\x00\x03" +
            b"\x00\x00\x00\x02"
        )

    def _bson_cstring(self, s: str) -> bytes:
        return s.encode("utf-8") + b"\x00"

    def _bson_string(self, s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack("<i", len(b) + 1) + b + b"\x00"

    def _bson_int32(self, n: int) -> bytes:
        return struct.pack("<i", int(n))

    def _bson_document(self, doc: dict) -> bytes:
        elems = bytearray()
        for k, v in doc.items():
            if isinstance(v, int):
                elems.extend(b"\x10")
                elems.extend(self._bson_cstring(k))
                elems.extend(self._bson_int32(v))
            elif isinstance(v, str):
                elems.extend(b"\x02")
                elems.extend(self._bson_cstring(k))
                elems.extend(self._bson_string(v))
        total = 4 + len(elems) + 1
        return struct.pack("<i", total) + elems + b"\x00"

    def _mongo_opmsg(self, doc: dict, request_id: int = 1) -> bytes:
        body = self._bson_document(doc)
        flags = struct.pack("<i", 0)
        section = b"\x00" + body
        msg_len = 16 + 4 + len(section)
        header = struct.pack("<iiii", msg_len, request_id, 0, 2013)
        return header + flags + section

    # ---- Oracle TNS CONNECT (minimal handshake) ----
    def _oracle_tns_connect_packet(self, host: str, port: int, service_name: str = "ORCL") -> bytes:
        conn_str = (
            f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port}))"
            f"(CONNECT_DATA=(SERVER=DEDICATED)(SERVICE_NAME={service_name})"
            f"(CID=(PROGRAM=db-detector)(HOST={host})(USER=scan))))"
        ).encode("ascii", errors="ignore")

        unknown1 = bytes.fromhex("00002000002000000000000000000000")

        version = 0x013A
        version_compatible = 0x012C
        service_options = 0x0000
        session_data_unit_size = 0x0800
        max_transmission_data_unit_size = 0x7FFF
        nt_protocol_characteristics = 0x7F08
        line_turnaround = 0x0000
        value_of_1_in_hw = 0x0100
        conn_data_len = len(conn_str)
        conn_data_offset = 58 + len(unknown1)
        conn_data_max_recv = 0x0200
        conn_data_flags_0 = 0x41
        conn_data_flags_1 = 0x41
        trace_cross_1 = 0
        trace_cross_2 = 0
        trace_unique_conn = 0
        reserved_4 = 0

        header_40 = struct.pack(
            ">HHHHHHHHHHHBBIIII",
            version,
            version_compatible,
            service_options,
            session_data_unit_size,
            max_transmission_data_unit_size,
            nt_protocol_characteristics,
            line_turnaround,
            value_of_1_in_hw,
            conn_data_len,
            conn_data_offset,
            conn_data_max_recv,
            conn_data_flags_0,
            conn_data_flags_1,
            trace_cross_1,
            trace_cross_2,
            trace_unique_conn,
            reserved_4,
        )
        padding_18 = b"\x00" * (58 - len(header_40))
        connect_payload = header_40 + padding_18 + unknown1 + conn_str

        tns_len = 8 + len(connect_payload)
        tns_hdr = struct.pack(">HHBBH", tns_len, 0x0000, 0x01, 0x00, 0x0000)
        return tns_hdr + connect_payload

    # --------------- Length-aware reads ---------------
    def _read_mysql_handshake(self, sock: socket.socket) -> bytes:
        # MySQL usually greets quickly, but can be delayed under load / reverse-DNS / gateways.
        time.sleep(0.02)
        hdr = self._recv_exact(sock, 4, total_timeout=max(self.probe_timeout, 4.0))
        if not hdr:
            return b""
        payload_len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
        if payload_len <= 0 or payload_len > 200000:
            return hdr
        payload = self._recv_exact(sock, payload_len, total_timeout=max(self.probe_timeout, 6.0))
        return hdr + (payload or b"")

    def _read_cassandra_frame(self, sock: socket.socket) -> bytes:
        hdr = self._recv_exact(sock, 9, total_timeout=max(self.probe_timeout, 6.0))
        if not hdr:
            return b""
        try:
            body_len = struct.unpack("!I", hdr[5:9])[0]
        except Exception:
            return hdr
        if body_len > 10_000_000:
            return hdr
        body = self._recv_exact(sock, body_len, total_timeout=max(self.probe_timeout, 6.0)) if body_len else b""
        return hdr + (body or b"")

    def _read_mssql_packet(self, sock: socket.socket) -> bytes:
        hdr = self._recv_exact(sock, 8, total_timeout=max(self.probe_timeout, 6.0))
        if not hdr:
            return b""
        try:
            total_len = struct.unpack("!H", hdr[2:4])[0]
        except Exception:
            return hdr
        if total_len < 8 or total_len > 65535:
            return hdr
        rest = self._recv_exact(sock, total_len - 8, total_timeout=max(self.probe_timeout, 6.0))
        return hdr + (rest or b"")

    def _read_mongo_message(self, sock: socket.socket) -> bytes:
        head = self._recv_any(sock, total_timeout=max(self.probe_timeout, 4.0), max_bytes=64)
        if len(head) < 4:
            return head
        msg_len = struct.unpack("<i", head[:4])[0]
        if msg_len < 16 or msg_len > 50_000_000:
            return head
        remaining = msg_len - len(head)
        if remaining <= 0:
            return head
        rest = self._recv_exact(sock, remaining, total_timeout=max(self.probe_timeout, 6.0))
        return head + (rest or b"")

    def _read_tns_packet(self, sock: socket.socket) -> bytes:
        hdr = self._recv_exact(sock, 8, total_timeout=max(self.probe_timeout, 6.0))
        if len(hdr) < 8:
            return hdr
        try:
            length = struct.unpack(">H", hdr[:2])[0]
        except Exception:
            return hdr
        if length < 8 or length > 65535:
            return hdr
        body = self._recv_exact(sock, length - 8, total_timeout=max(self.probe_timeout, 6.0))
        return hdr + (body or b"")

    # --------------- Scoring / fingerprints ---------------
    def _score(self, data: bytes, db_type: str) -> Optional[Tuple[float, str]]:
        """
        Returns (confidence, sentence) if the bytes strongly indicate db_type.
        """
        if not data:
            return None
        d = data.lower()

        # MySQL greeting framing: payload[0]=0x0A at offset 4
        if db_type == "MySQL" and len(data) >= 5 and data[4] == 0x0A:
            return 1.00, "MySQL responded with its native handshake greeting."

        # PostgreSQL SSLRequest response is 1 byte 'S' or 'N'
        if db_type == "PostgreSQL" and len(data) <= 8 and data[:1] in (b"S", b"N"):
            return 1.00, "PostgreSQL responded to the SSL negotiation probe."

        # Redis: PONG or auth gate errors
        if db_type == "Redis":
            if b"+pong" in d:
                return 1.00, "Redis replied to a PING request."
            if b"-noauth" in d or b"authentication required" in d:
                return 0.95, "Redis replied that authentication is required (common Redis behavior)."
            if b"-denied" in d and b"redis" in d:
                return 0.95, "Redis replied with an access-control error."

        # MongoDB: wire framing + hello metadata keys
        if db_type == "MongoDB" and len(data) >= 16:
            try:
                msg_len, _, _, opcode = struct.unpack("<iiii", data[:16])
            except Exception:
                msg_len, opcode = 0, 0
            if 16 <= msg_len <= 50_000_000 and opcode in (2013, 1):
                if b"iswritableprimary" in d or b"maxbsonobjectsize" in d or b"maxwireversion" in d:
                    return 1.00, "MongoDB replied to a hello/isMaster probe."
                return 0.95, "MongoDB replied with a valid wire-protocol message."

        # MSSQL: TDS framing
        if db_type == "MSSQL" and len(data) >= 8:
            pkt_type = data[0]
            try:
                length = struct.unpack("!H", data[2:4])[0]
            except Exception:
                length = 0
            if pkt_type in (0x04, 0x12, 0x10, 0x0E) and 8 <= length <= 65535:
                return 0.95, "MSSQL replied with a valid TDS packet."

        # Cassandra native protocol: response bit + capability fields
        if db_type == "Cassandra" and len(data) >= 1 and (data[0] & 0x80) == 0x80:
            if b"protocol_versions" in d or b"cql_version" in d or b"compression" in d:
                return 1.00, "Cassandra replied to a native-protocol OPTIONS request."
            return 0.95, "Cassandra replied with a valid native-protocol frame."

        # Oracle TNS: header type indicates listener behavior
        if db_type == "Oracle" and len(data) >= 8:
            pkt_type = data[4]  # 0x02 ACCEPT, 0x04 REFUSE, 0x05 REDIRECT, 0x06 DATA
            if pkt_type == 0x02:
                return 1.00, "Oracle listener accepted the Oracle Net (TNS) connection."
            if pkt_type == 0x04:
                return 0.95, "Oracle listener refused the Oracle Net (TNS) connection (still confirms Oracle)."
            if pkt_type == 0x05:
                return 0.95, "Oracle listener redirected the Oracle Net (TNS) connection (still confirms Oracle)."
            if pkt_type == 0x06:
                return 0.80, "Oracle listener sent Oracle Net (TNS) data in response."

        # HTTP-based products
        if db_type in {"Elasticsearch", "CouchDB", "InfluxDB", "Neo4j"} and d.startswith(b"http/"):
            if db_type == "Elasticsearch":
                if b"x-elastic-product:" in d:
                    return 1.00, "Elasticsearch identified itself via an HTTP product header."
                if b'"cluster_name"' in d and b'"version"' in d:
                    return 0.95, "Elasticsearch responded with cluster/version metadata over HTTP."
                return 0.80, "An HTTP service responded, consistent with Elasticsearch."

            if db_type == "CouchDB":
                if b'"couchdb"' in d and b"welcome" in d:
                    return 1.00, "CouchDB returned its welcome/metadata response over HTTP."
                if b"server:" in d and b"couchdb" in d:
                    return 0.95, "CouchDB identified itself via HTTP headers."
                return 0.80, "An HTTP service responded, consistent with CouchDB."

            if db_type == "InfluxDB":
                if b"x-influxdb-version" in d or b"204 no content" in d:
                    return 1.00, "InfluxDB identified itself via its ping/version behavior."
                return 0.80, "An HTTP service responded, consistent with InfluxDB."

            if db_type == "Neo4j":
                if b"neo4j_version" in d or b'realm="neo4j"' in d or b"neo4j" in d:
                    return 1.00, "Neo4j identified itself via an HTTP response."
                return 0.80, "An HTTP service responded, consistent with Neo4j."

        # Neo4j Bolt: server responds with a 4-byte version selection (non-zero)
        if db_type == "Neo4j" and len(data) == 4 and data != b"\x00\x00\x00\x00":
            return 1.00, "Neo4j replied to the Bolt handshake."

        return None

    # --------------- HTTP/HTTPS probe ---------------
    def _http_request(self, host: str, path: str) -> bytes:
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: db-detector\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

    def _probe_http_or_https(self, ip: str, port: int, path: str) -> bytes:
        # HTTP
        s, code = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
        self._dbg(f"[debug] connect {ip}:{port} (http) -> code={code}")
        if s:
            try:
                s.settimeout(max(self.probe_timeout, 2.0))
                s.sendall(self._http_request(ip, path))
                b = self._recv_any(s, total_timeout=max(self.probe_timeout, 3.0), max_bytes=65535)
                if b:
                    return b
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        # HTTPS
        s, code = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
        self._dbg(f"[debug] connect {ip}:{port} (https) -> code={code}")
        if not s:
            return b""
        try:
            tls = self._wrap_tls(s, server_name=ip)
            if not tls:
                return b""
            tls.sendall(self._http_request(ip, path))
            return self._recv_any(tls, total_timeout=max(self.probe_timeout, 4.0), max_bytes=65535)
        except Exception:
            return b""
        finally:
            try:
                s.close()
            except Exception:
                pass

    # --------------- User-friendly fallback reasoning ---------------
    def _open_port_reason(self, db_type: str, port: int, behavior: str) -> Tuple[float, str, str]:
        """
        behavior: "closed" | "silent" | "no-match"
        Returns: (confidence, sentence, evidence_tag)
        """
        if db_type == "Cassandra" and port in CASSANDRA_INTERNODE_PORTS:
            conf = 0.55
            sentence = (
                "This port is open and matches Cassandra’s internode (cluster-to-cluster) port. "
                "Internode ports commonly do not respond to client-style probes, especially when TLS or peer restrictions are enabled."
            )
            return conf, sentence, "open port"

        # For classic DB client ports: if open but silent, make it "possible" not "open-only"
        if behavior in ("silent", "closed"):
            conf = 0.55
            if behavior == "closed":
                sentence = (
                    f"The port is open and matches {db_type}’s usual port, but the service closed the connection immediately. "
                    "This can happen with access controls, security devices, or services that only talk to approved clients."
                )
            else:
                sentence = (
                    f"The port is open and matches {db_type}’s usual port, but the service did not send an identifiable response. "
                    "This can happen when encryption is required, access is restricted, or a security device is in front of the service."
                )
            return conf, sentence, "open port"

        # No match after receiving data
        conf = 0.35
        sentence = (
            f"The port is open and we received data, but it did not match expected {db_type} protocol fingerprints."
        )
        return conf, sentence, "open port"

    # --------------- Probe known (single port) ---------------
    def probe_known(self, ip: str, port: int, db_type: str) -> DatabaseDetection:
        best: Optional[Tuple[float, str]] = None  # (confidence, sentence)

        def consider(data: bytes):
            nonlocal best
            scored = self._score(data, db_type)
            if not scored:
                return
            conf, sentence = scored
            if best is None or conf > best[0]:
                best = (conf, sentence)

        # Quick connect to determine peer behavior (silent vs closed vs data)
        behavior = "silent"
        pre_data: bytes = b""
        s0, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
        if s0:
            try:
                behavior = self._peek_status(s0, wait=min(self.greeting_wait, max(0.1, self.probe_timeout)))
                if behavior == "data":
                    try:
                        s0.settimeout(max(0.2, min(1.0, self.probe_timeout)))
                        pre_data = s0.recv(64, socket.MSG_PEEK)
                    except Exception:
                        pre_data = b""
            finally:
                try:
                    s0.close()
                except Exception:
                    pass

        # ---- Cassandra internode ports ----
        if db_type == "Cassandra" and port in CASSANDRA_INTERNODE_PORTS:
            conf, sentence, ev = self._open_port_reason(db_type, port, behavior)
            return DatabaseDetection(ip=ip, port=port, db_type=db_type, confidence=conf, verified=self._verified(conf), reason=self._reason(conf, sentence, ev))

        # ---- MySQL ----
        if db_type == "MySQL":
            # Plaintext read
            s, code = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
            if s:
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    b = self._read_mysql_handshake(s)
                    self._dump_bytes(f"{ip}:{port} MySQL greeting", b)
                    consider(b)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            # TLS fallback if enabled or if plaintext gave nothing
            if (best is None) and (self.wakeup_enabled or behavior != "data"):
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                if s:
                    try:
                        tls = self._wrap_tls(s, server_name=ip)
                        if tls:
                            b2 = self._read_mysql_handshake(tls)
                            self._dump_bytes(f"{ip}:{port} MySQL greeting (TLS)", b2)
                            consider(b2)
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

            # One bounded retry with longer wait can help on slow greetings
            if best is None and self.probe_timeout < 6.0:
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.2))
                if s:
                    try:
                        saved = self.probe_timeout
                        self.probe_timeout = min(6.0, saved * 2.0)
                        b3 = self._read_mysql_handshake(s)
                        self._dump_bytes(f"{ip}:{port} MySQL greeting (retry)", b3)
                        consider(b3)
                    finally:
                        self.probe_timeout = saved
                        try:
                            s.close()
                        except Exception:
                            pass

        # ---- PostgreSQL ----
        elif db_type == "PostgreSQL":
            s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
            if s:
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    s.sendall(self._postgres_ssl_request())
                    b = self._recv_exact(s, 1, total_timeout=max(self.probe_timeout, 3.0))
                    self._dump_bytes(f"{ip}:{port} PostgreSQL SSLRequest reply", b)
                    consider(b)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

        # ---- Redis ----
        elif db_type == "Redis":
            # plaintext
            s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
            if s:
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    s.sendall(b"PING\r\n")
                    b = self._recv_any(s, total_timeout=max(self.probe_timeout, 2.0), max_bytes=512)
                    self._dump_bytes(f"{ip}:{port} Redis PING reply", b)
                    consider(b)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            # TLS fallback
            if best is None and (self.wakeup_enabled or behavior != "data"):
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                if s:
                    try:
                        tls = self._wrap_tls(s, server_name=ip)
                        if tls:
                            tls.sendall(b"PING\r\n")
                            b2 = self._recv_any(tls, total_timeout=max(self.probe_timeout, 2.0), max_bytes=512)
                            self._dump_bytes(f"{ip}:{port} Redis PING reply (TLS)", b2)
                            consider(b2)
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

        # ---- MongoDB ----
        elif db_type == "MongoDB":
            # plaintext
            s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
            if s:
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    s.sendall(self._mongo_opmsg({"hello": 1, "$db": "admin"}, request_id=1))
                    b = self._read_mongo_message(s)
                    self._dump_bytes(f"{ip}:{port} MongoDB hello reply", b)
                    consider(b)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            # TLS fallback
            if best is None and (self.wakeup_enabled or behavior != "data"):
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                if s:
                    try:
                        tls = self._wrap_tls(s, server_name=ip)
                        if tls:
                            tls.sendall(self._mongo_opmsg({"hello": 1, "$db": "admin"}, request_id=2))
                            b2 = self._read_mongo_message(tls)
                            self._dump_bytes(f"{ip}:{port} MongoDB hello reply (TLS)", b2)
                            consider(b2)
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

        # ---- MSSQL ----
        elif db_type == "MSSQL":
            # try both prelogin variants
            for name, pkt in (("prelogin_v1", self._mssql_prelogin_v1()), ("prelogin_v2", self._mssql_prelogin_v2())):
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                if not s:
                    continue
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    s.sendall(pkt)
                    b = self._read_mssql_packet(s)
                    self._dump_bytes(f"{ip}:{port} MSSQL {name} reply", b)
                    consider(b)
                    if best and best[0] >= 0.95:
                        break
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

        # ---- Cassandra (client/CQL ports) ----
        elif db_type == "Cassandra":
            # Only do native protocol OPTIONS on known CQL client ports (9042/9142).
            # For 9160 (old thrift), do not attempt thrift fingerprint.
            if port in CASSANDRA_CQL_PORTS:
                # plaintext
                for v in (0x05, 0x04, 0x03):
                    s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                    if not s:
                        continue
                    try:
                        s.settimeout(max(self.probe_timeout, 2.0))
                        s.sendall(self._cassandra_options(v))
                        b = self._read_cassandra_frame(s)
                        self._dump_bytes(f"{ip}:{port} Cassandra OPTIONS v{v} reply", b)
                        consider(b)
                        if best and best[0] >= 1.00:
                            break
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

                # TLS fallback
                if best is None and (self.wakeup_enabled or behavior != "data"):
                    for v in (0x05, 0x04, 0x03):
                        s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                        if not s:
                            continue
                        try:
                            tls = self._wrap_tls(s, server_name=ip)
                            if not tls:
                                continue
                            tls.sendall(self._cassandra_options(v))
                            b2 = self._read_cassandra_frame(tls)
                            self._dump_bytes(f"{ip}:{port} Cassandra OPTIONS v{v} reply (TLS)", b2)
                            consider(b2)
                            if best and best[0] >= 1.00:
                                break
                        finally:
                            try:
                                s.close()
                            except Exception:
                                pass

            else:
                # Non-CQL Cassandra port (e.g. 9160): treat open as possible but not verifiable with these probes.
                conf, sentence, ev = self._open_port_reason(db_type, port, behavior)
                return DatabaseDetection(ip=ip, port=port, db_type=db_type, confidence=conf, verified=self._verified(conf), reason=self._reason(conf, sentence, ev))

        # ---- HTTP-family ----
        elif db_type in {"Elasticsearch", "CouchDB", "InfluxDB", "Neo4j"}:
            path = "/ping" if db_type == "InfluxDB" else "/"
            b = self._probe_http_or_https(ip, port, path)
            self._dump_bytes(f"{ip}:{port} {db_type} HTTP/HTTPS reply", b)
            consider(b)

        # ---- Neo4j Bolt ----
        elif db_type == "Neo4j" and port == 7687:
            # plaintext
            s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
            if s:
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    s.sendall(self._neo4j_bolt_handshake())
                    b = self._recv_exact(s, 4, total_timeout=max(self.probe_timeout, 2.0))
                    self._dump_bytes(f"{ip}:{port} Neo4j Bolt reply", b)
                    consider(b)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            # TLS fallback
            if best is None and (self.wakeup_enabled or behavior != "data"):
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                if s:
                    try:
                        tls = self._wrap_tls(s, server_name=ip)
                        if tls:
                            tls.sendall(self._neo4j_bolt_handshake())
                            b2 = self._recv_exact(tls, 4, total_timeout=max(self.probe_timeout, 2.0))
                            self._dump_bytes(f"{ip}:{port} Neo4j Bolt reply (TLS)", b2)
                            consider(b2)
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

        # ---- Oracle ----
        elif db_type == "Oracle":
            # Plain TNS
            s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
            if s:
                try:
                    s.settimeout(max(self.probe_timeout, 2.0))
                    pkt = self._oracle_tns_connect_packet(ip, port, service_name="ORCL")
                    s.sendall(pkt)
                    b = self._read_tns_packet(s)
                    self._dump_bytes(f"{ip}:{port} Oracle TNS reply", b)
                    consider(b)
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            # TLS-wrapped Oracle (TCPS) fallback
            if best is None and (self.wakeup_enabled or behavior != "data"):
                s, _ = self._connect_ex(ip, port, timeout=max(self.connect_timeout, 1.0))
                if s:
                    try:
                        tls = self._wrap_tls(s, server_name=ip)
                        if tls:
                            pkt = self._oracle_tns_connect_packet(ip, port, service_name="ORCL")
                            tls.sendall(pkt)
                            b2 = self._read_tns_packet(tls)
                            self._dump_bytes(f"{ip}:{port} Oracle TNS reply (TLS)", b2)
                            consider(b2)
                    finally:
                        try:
                            s.close()
                        except Exception:
                            pass

        # ---- Finalize: if we got a real fingerprint ----
        if best:
            conf, sentence = best
            return DatabaseDetection(
                ip=ip,
                port=port,
                db_type=db_type,
                confidence=conf,
                verified=self._verified(conf),
                reason=self._reason(conf, sentence, "protocol handshake"),
            )

        # ---- Otherwise: open-port evidence with better explanation ----
        # Determine behavior again for better messaging if needed
        fallback_behavior = behavior
        if fallback_behavior not in ("closed", "silent"):
            # If we didn't prove it and we didn't explicitly see data, treat as silent
            fallback_behavior = "silent"

        conf, sentence, ev = self._open_port_reason(db_type, port, fallback_behavior)
        return DatabaseDetection(
            ip=ip,
            port=port,
            db_type=db_type,
            confidence=conf,
            verified=self._verified(conf),
            reason=self._reason(conf, sentence, ev),
        )

    # --------------- Fingerprint open port (discovery) ---------------
    def fingerprint_open(self, ip: str, port: int) -> Optional[DatabaseDetection]:
        candidates = [
            "MySQL", "PostgreSQL", "MongoDB", "Redis", "MSSQL",
            "Cassandra", "Elasticsearch", "CouchDB", "InfluxDB", "Neo4j", "Oracle",
        ]

        saved_timeout = self.probe_timeout
        self.probe_timeout = min(saved_timeout, 2.0)
        best: Optional[DatabaseDetection] = None
        try:
            for db in candidates:
                det = self.probe_known(ip, port, db)
                if det.confidence >= 1.00:
                    return det
                if det.confidence >= 0.95:
                    if best is None or det.confidence > best.confidence:
                        best = det
        finally:
            self.probe_timeout = saved_timeout

        return best if best and best.confidence >= 0.95 else None


def write_results(detections: List[DatabaseDetection], output_file: str):
    if not detections:
        print("[!] No databases detected")
        return
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "port", "db_type", "confidence", "verified", "reason"])
            writer.writeheader()
            for d in sorted(detections, key=lambda x: (x.ip, x.port, x.db_type)):
                writer.writerow(asdict(d))
        print(f"[+] Results written to: {output_file}")
    except Exception as e:
        print(f"[!] Error writing results: {e}")
        sys.exit(1)


def print_summary(detections: List[DatabaseDetection]):
    if not detections:
        return
    db_counts: Dict[str, int] = {}
    verified_count = 0
    for d in detections:
        db_counts[d.db_type] = db_counts.get(d.db_type, 0) + 1
        if d.verified:
            verified_count += 1
    print()
    print("─" * 65)
    print("SUMMARY")
    print("─" * 65)
    print(f" Total:    {len(detections)} detections")
    print(f" Verified: {verified_count} ({verified_count/len(detections)*100:.1f}%)")
    print()
    for db_type, count in sorted(db_counts.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * min(count, 40)
        print(f" {db_type:<18} {count:>3}  {bar}")
    print("─" * 65)


# -----------------------
# TWO-PASS connect sweep + per-IP limiter
# -----------------------
def bounded_map_with_ip_limit(
    executor: concurrent.futures.Executor,
    func,
    items: Iterator[Any],
    max_inflight: int,
) -> Iterator[Any]:
    inflight: Dict[concurrent.futures.Future, Any] = {}

    def submit_one() -> bool:
        try:
            item = next(items)
        except StopIteration:
            return False
        fut = executor.submit(func, item)
        inflight[fut] = item
        return True

    for _ in range(max_inflight):
        if not submit_one():
            break

    while inflight:
        done, _ = concurrent.futures.wait(inflight.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
        for fut in done:
            inflight.pop(fut, None)
            yield fut.result()
            submit_one()


def scan_ips(
    ips: List[str],
    input_file: str,
    output_file: str,
    workers: int,
    connect_timeout: float,
    probe_timeout: float,
    greeting_wait: float,
    wakeup_enabled: bool,
    quiet: bool,
    debug: bool,
    debug_full: bool,
    mode: str,  # "known" | "top" | "all"
    top_ports_count: int,
    excluded_ports: Set[int],
    per_ip_limit: int,
):
    if not quiet:
        print(BANNER.format(version=VERSION))
        print()

    print(f"[*] Reading IPs from: {input_file}")
    print(f"[*] Found {len(ips)} valid IPv4 addresses")
    if debug:
        print("[*] Debug: enabled (payloads to stderr)")

    print(
        f"[*] Mode: {mode} | workers={workers} | per-ip-limit={per_ip_limit} | "
        f"connect-timeout={connect_timeout}s | probe-timeout={probe_timeout}s | greeting-wait={greeting_wait}s | "
        f"wakeup={'on' if wakeup_enabled else 'off'}"
    )
    if mode != "known":
        print(f"[*] Discovery excludes: {len(excluded_ports)} port(s)")
    print()

    detector = DatabaseDetector(
        connect_timeout=connect_timeout,
        probe_timeout=probe_timeout,
        greeting_wait=greeting_wait,
        wakeup_enabled=wakeup_enabled,
        debug=debug,
        debug_full=debug_full,
    )

    ip_sems: Dict[str, threading.Semaphore] = {ip: threading.Semaphore(per_ip_limit) for ip in ips}

    def check_open(item: Tuple[str, int, Optional[str]]) -> Tuple[str, int, Optional[str], bool]:
        ip, port, db_type = item
        sem = ip_sems[ip]
        sem.acquire()
        try:
            s, code = detector._connect_ex(ip, port, timeout=connect_timeout)
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            return ip, port, db_type, (code == 0)
        finally:
            sem.release()

    # ---- Targets ----
    known_ports_sorted = sorted(DB_PORTS.keys())

    known_targets: List[Tuple[str, int, str]] = []
    for ip in ips:
        for p in known_ports_sorted:
            known_targets.append((ip, p, DB_PORTS[p]))

    discovery_targets: List[Tuple[str, int, Optional[str]]] = []
    if mode == "top":
        scan_ports = build_top_ports_list(top_ports_count)
        known_set = set(known_ports_sorted)
        for ip in ips:
            for p in scan_ports:
                if p in known_set:
                    continue
                if p in excluded_ports and p not in CANONICAL_DB_PORTS:
                    continue
                discovery_targets.append((ip, p, DB_PORTS.get(p)))
    elif mode == "all":
        known_set = set(known_ports_sorted)
        for ip in ips:
            for p in range(1, 65536):
                if p in known_set:
                    continue
                if p in excluded_ports and p not in CANONICAL_DB_PORTS:
                    continue
                discovery_targets.append((ip, p, DB_PORTS.get(p)))

    # ---- Phase 1: connect sweep ----
    open_known: List[Tuple[str, int, str]] = []
    open_unknown: List[Tuple[str, int]] = []

    max_inflight = min(800, max(200, workers * 2))

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        # Pass A
        itA = iter(known_targets)
        scannedA = 0
        for ip, port, db_type, is_open in bounded_map_with_ip_limit(ex, check_open, itA, max_inflight=max_inflight):
            scannedA += 1
            if is_open:
                open_known.append((ip, port, db_type))
        if not quiet:
            print(f"[*] Phase1A complete (known ports): scanned={scannedA} open_known={len(open_known)} elapsed={time.time()-t0:.1f}s")

        # Pass B
        if discovery_targets:
            tB = time.time()
            itB = iter(discovery_targets)
            scannedB = 0
            for ip, port, db_type, is_open in bounded_map_with_ip_limit(ex, check_open, itB, max_inflight=max_inflight):
                scannedB += 1
                if is_open:
                    if db_type is not None:
                        open_known.append((ip, port, db_type))
                    else:
                        open_unknown.append((ip, port))
            if not quiet:
                print(f"[*] Phase1B complete (discovery): scanned={scannedB} open_known={len(open_known)} open_unknown={len(open_unknown)} elapsed={time.time()-tB:.1f}s")

    # ---- Phase 2: probe ----
    detections: List[DatabaseDetection] = []

    def probe_known_task(item: Tuple[str, int, str]) -> DatabaseDetection:
        ip, port, db_type = item
        sem = ip_sems[ip]
        sem.acquire()
        try:
            return detector.probe_known(ip, port, db_type)
        finally:
            sem.release()

    def probe_unknown_task(item: Tuple[str, int]) -> Optional[DatabaseDetection]:
        ip, port = item
        sem = ip_sems[ip]
        sem.acquire()
        try:
            return detector.fingerprint_open(ip, port)
        finally:
            sem.release()

    t2 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for det in ex.map(probe_known_task, open_known):
            detections.append(det)

        if mode != "known" and open_unknown:
            for det in ex.map(probe_unknown_task, open_unknown):
                if det:
                    detections.append(det)

    if not quiet:
        print(f"[*] Phase2 complete: probes={len(open_known)+len(open_unknown)} elapsed={time.time()-t2:.1f}s")

    print(f"[+] Scan complete: {len(detections)} detections")
    write_results(detections, output_file)
    print_summary(detections)


def list_supported_databases():
    print(BANNER.format(version=VERSION))
    print()
    print("SUPPORTED DATABASES / PORTS")
    print("─" * 65)
    seen = set()
    for port, db_type in sorted(DB_PORTS.items(), key=lambda x: (x[1], x[0])):
        if db_type not in seen:
            ports = [str(p) for p, dt in DB_PORTS.items() if dt == db_type]
            ports_sorted = ", ".join(sorted(ports, key=lambda s: int(s)))
            print(f" {db_type:<20} Port(s): {ports_sorted}")
            seen.add(db_type)
    print("─" * 65)
    print()
    print("NOTES")
    print("─" * 65)
    print(" Cassandra 7000/7001 are internode ports and often do not respond to client probes.")
    print(" Cassandra client (CQL) is usually 9042/9142.")
    print("─" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="Database Detector - Fast database identification from IP lists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("input", nargs="?", help="Input file with IPv4 addresses")
    parser.add_argument("-o", "--output", default="db_detections.csv", help="Output CSV file")

    parser.add_argument("--workers", type=int, default=300, help="Global worker threads (default 300, max 2000)")
    parser.add_argument("--per-ip-limit", type=int, default=24, help="Max concurrent sockets per IP (default 24)")

    parser.add_argument("--connect-timeout", type=float, default=0.80, help="Connect timeout for sweep (default 0.80s)")
    parser.add_argument("--probe-timeout", type=float, default=3.0, help="Probe timeout for protocol checks (default 3.0s)")

    # New: greeting wait used to classify behavior quickly (closed vs silent vs data)
    parser.add_argument("--greeting-wait", type=float, default=0.25, help="Short wait to see if server sends data quickly (default 0.25s)")

    # New: optional "wakeup" behavior to attempt TLS fallbacks more aggressively
    parser.add_argument("--wakeup", action="store_true", help="Enable extra fallback behaviors (more TLS attempts; may be slower/noisier)")

    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument("-l", "--list", action="store_true", help="List supported databases/ports")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")

    parser.add_argument("--debug", action="store_true", help="Debug connect + payload output to stderr")
    parser.add_argument("--debug-full", action="store_true", help="Dump full responses (otherwise first 4KB)")
    parser.add_argument("--debug-payload", action="store_true", help="Alias for --debug (compat)")

    # DEFAULT = known only
    parser.add_argument("--discover-top", action="store_true", help="Enable discovery scan on TOP ports list")
    parser.add_argument("--all-ports", action="store_true", help="Enable discovery across 1-65535 (slowest)")
    parser.add_argument("--top-ports", type=int, default=1500, help="Top ports count used for --discover-top (default 1500)")

    parser.add_argument("--no-default-excludes", action="store_true", help="Disable default noisy-port exclusions")
    parser.add_argument("--exclude-ports", default="", help='Extra ports to exclude, e.g. "22,25,53,135-139,445,3389"')

    args = parser.parse_args()

    if args.list:
        list_supported_databases()
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if args.workers < 1 or args.workers > 2000:
        print("[!] Error: --workers must be between 1 and 2000")
        sys.exit(1)

    if args.per_ip_limit < 1 or args.per_ip_limit > 500:
        print("[!] Error: --per-ip-limit must be between 1 and 500")
        sys.exit(1)

    if args.connect_timeout < 0.01 or args.connect_timeout > 5.0:
        print("[!] Error: --connect-timeout must be between 0.01 and 5.0 seconds")
        sys.exit(1)

    if args.probe_timeout < 0.1 or args.probe_timeout > 30.0:
        print("[!] Error: --probe-timeout must be between 0.1 and 30 seconds")
        sys.exit(1)

    if args.greeting_wait < 0.05 or args.greeting_wait > 5.0:
        print("[!] Error: --greeting-wait must be between 0.05 and 5.0 seconds")
        sys.exit(1)

    debug = args.debug or args.debug_payload
    debug_full = args.debug_full

    ips_set = read_ips_from_file(args.input)
    ips = sorted(ips_set)

    # Mode decision
    if args.all_ports:
        mode = "all"
    elif args.discover_top:
        mode = "top"
    else:
        mode = "known"

    # Guardrail: keep user choice unless they explicitly asked for all ports
    if len(ips) > LARGE_INPUT_THRESHOLD and mode == "all" and not args.all_ports:
        mode = "top"

    excluded_ports: Set[int] = set()
    if mode in ("top", "all"):
        if not args.no_default_excludes:
            excluded_ports.update(DEFAULT_EXCLUDE_PORTS)
        excluded_ports.update(parse_portspec(args.exclude_ports))
        excluded_ports.difference_update(CANONICAL_DB_PORTS)

    try:
        scan_ips(
            ips=ips,
            input_file=args.input,
            output_file=args.output,
            workers=args.workers,
            connect_timeout=args.connect_timeout,
            probe_timeout=args.probe_timeout,
            greeting_wait=args.greeting_wait,
            wakeup_enabled=args.wakeup,
            quiet=args.quiet,
            debug=debug,
            debug_full=debug_full,
            mode=mode,
            top_ports_count=args.top_ports,
            excluded_ports=excluded_ports,
            per_ip_limit=args.per_ip_limit,
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
