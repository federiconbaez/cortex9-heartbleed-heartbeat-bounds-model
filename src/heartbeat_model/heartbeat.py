"""tls1_process_heartbeat / dtls1_process_heartbeat before and after 96db9023.

Versions (OpenSSL 1.0.1 branch):
  "1.0.1f" - ssl/t1_lib.c and ssl/d1_both.c at 0d7717fc (parent of 96db9023)
  "1.0.1g" - 96db9023 "Add heartbeat extension bounds check."

There is no TLS here. A "record" is a Python bytes object standing for
s->s3->rrec.data[0 .. rrec.length). Whatever lies after it is a SIMULATED
region (`SimulatedArena`): synthetic bytes, each tagged with its origin.
No real process memory is read, and nothing is sent anywhere.
"""
from dataclasses import dataclass

VERSIONS = ("1.0.1f", "1.0.1g")
IMPLS = ("tls", "dtls")
TLS1_HB_REQUEST, TLS1_HB_RESPONSE = 1, 2
PADDING = 16                      # unsigned int padding = 16
SSL3_RT_MAX_PLAIN_LENGTH = 16384  # ssl/ssl3.h


@dataclass(frozen=True)
class Byte:
    value: int
    origin: str   # "record" | "simulated"
    offset: int   # offset from rrec.data[0]


class SimulatedArena:
    """rrec.data[0..len) followed by synthetic bytes (never real memory).

    The synthetic value at offset k >= len is (0xA5 ^ k) & 0xFF; only its
    origin matters to the model.
    """

    def __init__(self, record: bytes):
        self.record = bytes(record)

    def at(self, k: int) -> Byte:
        if k < len(self.record):
            return Byte(self.record[k], "record", k)
        return Byte((0xA5 ^ k) & 0xFF, "simulated", k)


def process(version: str, impl: str, record: bytes) -> dict:
    if version not in VERSIONS or impl not in IMPLS:
        raise ValueError((version, impl))
    a = SimulatedArena(record)
    length = len(record)
    out = {"version": version, "impl": impl, "rrec_length": length,
           "record_too_long": length > SSL3_RT_MAX_PLAIN_LENGTH}
    fixed = version == "1.0.1g"
    if fixed and 1 + 2 + 16 > length:           # t1_lib.c l.2597 / d1_both.c l.1468 (96db9023)
        return dict(out, action="DISCARD", reason="1 + 2 + 16 > rrec.length")
    p = 0
    hbtype = a.at(p); p += 1                    # hbtype = *p++
    hi, lo = a.at(p), a.at(p + 1); p += 2       # n2s(p, payload)
    payload = (hi.value << 8) | lo.value
    header_reads = [hbtype, hi, lo]
    out.update(hbtype=hbtype.value, payload=payload,
               header_simulated_bytes=sum(b.origin == "simulated" for b in header_reads))
    if fixed and 1 + 2 + payload + 16 > length:  # t1_lib.c l.2601 / d1_both.c l.1472
        return dict(out, action="DISCARD", reason="1 + 2 + payload + 16 > rrec.length")
    pl = p
    if hbtype.value == TLS1_HB_REQUEST:
        write_length = 1 + 2 + payload + PADDING
        if fixed and impl == "dtls" and write_length > SSL3_RT_MAX_PLAIN_LENGTH:
            # d1_both.c l.1484 (DTLS only)
            return dict(out, action="DISCARD", reason="write_length > SSL3_RT_MAX_PLAIN_LENGTH")
        # memcpy(bp, pl, payload): t1_lib.c l.2616 (0d7717fc) / l.2620 (96db9023)
        echoed = [a.at(pl + i) for i in range(payload)]
        sim = sum(b.origin == "simulated" for b in echoed)
        pad_in_echo = (sum(1 for b in echoed if b.origin == "record" and b.offset >= length - PADDING)
                       if length >= 1 + 2 + PADDING else None)
        return dict(out, action="RESPOND", response_length=3 + payload + PADDING,
                    echoed=payload, echoed_simulated=sim, echoed_record=payload - sim,
                    echoed_from_last16=pad_in_echo,
                    first_simulated_offset=next((b.offset for b in echoed if b.origin == "simulated"), None))
    if hbtype.value == TLS1_HB_RESPONSE:
        return dict(out, action="NO_RESPONSE", reason="response: sequence check only")
    return dict(out, action="NO_RESPONSE", reason="unknown type ignored")


def leaked(r: dict) -> int:
    """Simulated bytes that would leave in the response (header reads excluded)."""
    return r.get("echoed_simulated", 0)


def record(hbtype: int, payload_len_field: int, body: bytes) -> bytes:
    return bytes([hbtype, payload_len_field >> 8, payload_len_field & 0xFF]) + body
