"""Sweep over record lengths and payload length fields (all in memory)."""
from .heartbeat import IMPLS, TLS1_HB_REQUEST, VERSIONS, leaked, process, record

LENGTHS = range(0, 65)
FIELDS = tuple(range(0, 81)) + (255, 256, 1000, 16384, 65535)


def cases():
    for total in LENGTHS:
        for field in FIELDS:
            hdr = record(TLS1_HB_REQUEST, field, b"")
            rec = (hdr + bytes(range(256)) * 1)[:total] if total >= 3 else hdr[:total]
            yield total, field, rec


def sweep():
    rows = {}
    for total, field, rec in cases():
        for v in VERSIONS:
            for impl in IMPLS:
                r = process(v, impl, rec)
                k = (v, impl)
                c = rows.setdefault(k, {"records": 0, "respond": 0, "discard": 0,
                                        "leaking_records": 0, "simulated_bytes_echoed": 0,
                                        "max_leak": 0, "simulated_header_reads": 0,
                                        "echoed_padding_records": 0})
                c["records"] += 1
                c["respond"] += r["action"] == "RESPOND"
                c["discard"] += r["action"] == "DISCARD"
                n = leaked(r)
                c["leaking_records"] += n > 0
                c["simulated_bytes_echoed"] += n
                c["max_leak"] = max(c["max_leak"], n)
                c["simulated_header_reads"] += r.get("header_simulated_bytes", 0) > 0
                c["echoed_padding_records"] += bool(r.get("echoed_from_last16"))
    return rows
