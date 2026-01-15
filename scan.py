#!/usr/bin/env python3
"""
Simple IP scanner (host discovery + basic TCP port check)

Use only on networks/systems you own or have explicit permission to test.
This does *not* use ICMP ping (which often needs elevated privileges); it
treats a host as "up" if at least one TCP port connects successfully.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Dict, Any, Tuple


def parse_targets(target: str) -> List[str]:
    """Accept a CIDR (e.g., 192.168.1.0/24) or a single IP."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        ipaddress.ip_address(target)  # validate single IP
        return [target]


def parse_ports(ports: str) -> List[int]:
    out: List[int] = []
    for p in ports.split(","):
        p = p.strip()
        if not p:
            continue
        n = int(p)
        if not (1 <= n <= 65535):
            raise ValueError(f"Invalid port: {n}")
        out.append(n)
    if not out:
        raise ValueError("No ports specified.")
    return sorted(set(out))


def try_connect(ip: str, port: int, timeout: float) -> bool:
    """Return True if TCP connect succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def scan_ip(ip: str, ports: List[int], timeout: float) -> Dict[str, Any]:
    open_ports: List[int] = []
    for port in ports:
        if try_connect(ip, port, timeout):
            open_ports.append(port)

    if not open_ports:
        return {"ip": ip, "up": False, "open_ports": []}

    # Optional reverse DNS lookup
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass

    return {"ip": ip, "up": True, "open_ports": open_ports, "hostname": hostname}


def main() -> int:
    ap = argparse.ArgumentParser(description="Quick TCP-based IP scanner")
    ap.add_argument("target", help="CIDR or single IP (e.g., 192.168.1.0/24 or 192.168.1.10)")
    ap.add_argument("-p", "--ports", default="22,80,443", help="Comma-separated ports to check (default: 22,80,443)")
    ap.add_argument("-t", "--timeout", type=float, default=0.5, help="Socket timeout seconds (default: 0.5)")
    ap.add_argument("-w", "--workers", type=int, default=200, help="Max concurrent workers (default: 200)")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args()

    ips = parse_targets(args.target)
    ports = parse_ports(args.ports)
    workers = max(1, min(args.workers, 2000))

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_ip, ip, ports, args.timeout): ip for ip in ips}
        for fut in as_completed(futures):
            results.append(fut.result())

    # keep output stable
    results.sort(key=lambda r: tuple(int(x) for x in r["ip"].split(".")) if "." in r["ip"] else r["ip"])

    if args.json:
        print(json.dumps([r for r in results if r["up"]], indent=2))
    else:
        up = [r for r in results if r["up"]]
        if not up:
            print("No hosts detected (on the selected ports).")
            return 0

        for r in up:
            host = f" ({r['hostname']})" if r.get("hostname") else ""
            ports_str = ",".join(str(p) for p in r["open_ports"])
            print(f"{r['ip']}{host}  open: {ports_str}")

        print(f"\nDetected {len(up)} host(s) up (by TCP connect) out of {len(results)} scanned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
