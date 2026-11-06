"""CLI: python -m heartbeat_model check --type 1 --length-field N --body-len M [--impl tls|dtls]

Builds a record in memory (type, 16-bit payload length field, M body bytes
of 0x42) and shows what each version does with it. No network."""
import argparse
import json

from .heartbeat import IMPLS, VERSIONS, process, record


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="heartbeat_model")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--type", type=int, default=1)
    c.add_argument("--length-field", type=int, required=True)
    c.add_argument("--body-len", type=int, required=True)
    c.add_argument("--impl", choices=IMPLS, default="tls")
    a = ap.parse_args(argv)
    if not (0 <= a.length_field <= 0xFFFF and 0 <= a.body_len <= 70000):
        ap.error("length field must fit 16 bits; body-len <= 70000")
    rec = record(a.type, a.length_field, b"\x42" * a.body_len)
    print(json.dumps({v: process(v, a.impl, rec) for v in VERSIONS}, indent=2))
    return 0
