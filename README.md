# ipscanner

A quick **TCP-based IP range scanner** for basic host discovery and port checks.

It treats a host as **“up”** if it can successfully **TCP connect** to at least one of the ports you specify. This avoids ICMP “ping” requirements (which often need admin/root privileges) but also means results depend on which ports you scan.

## Responsible Use

Use only on networks/systems you **own** or have **explicit permission** to test.

## Requirements

- Python 3.9+ (3.8 will usually work, but 3.9+ is recommended)
- No external dependencies (standard library only)

## Install / Run

1. Save the script as `ipscanner.py`
2. Run it from a terminal:

```bash
python ipscanner.py 192.168.1.0/24
