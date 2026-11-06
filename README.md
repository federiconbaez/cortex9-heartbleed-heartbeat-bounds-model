# cortex9-heartbleed-heartbeat-bounds-model

An offline model of the missing bounds check in OpenSSL's heartbeat handler
(CVE-2014-0160, "Heartbleed"). It covers `tls1_process_heartbeat()` and
`dtls1_process_heartbeat()` before and after commit 96db9023 (1.0.1g).

**There is no TLS here.** The model opens no sockets and links no OpenSSL.
It does not read real process memory. A "record" is a Python `bytes`
object that stands for `s->s3->rrec.data[0 .. rrec.length)`. What comes
after it is a simulated region (`SimulatedArena`). Every byte in that
region is synthetic and tagged `origin="simulated"`. The model counts how
many tagged bytes would end up in the heartbeat response.

## What is modelled

| Step | 1.0.1f (0d7717fc) | 1.0.1g (96db9023) |
|---|---|---|
| `1 + 2 + 16 > rrec.length` | not checked | silent discard (t1_lib.c l.2597, d1_both.c l.1468) |
| `hbtype = *p++; n2s(p, payload)` | read even past the record | read only after the check above |
| `1 + 2 + payload + 16 > rrec.length` | not checked | silent discard (t1_lib.c l.2601, d1_both.c l.1472) |
| DTLS `write_length > 16384` | not checked | discard (d1_both.c l.1484) |
| `memcpy(bp, pl, payload)` | copies `payload` bytes from `pl` | same, now within the record |

Invariant: a response never contains a byte from outside
`rrec.data[0..rrec.length)`.

## Results (`results/`, regenerable)

The sweep covers record lengths 0–64 and 86 values of the payload length
field, giving 5,590 records per version and implementation:

| version | records leaking | simulated bytes echoed | max per response |
|---|---|---|---|
| 1.0.1f | 3,551 | 8,972,661 | 65,535 |
| 1.0.1g | 0 | 0 | 0 |

Two further observations:

- In 1.0.1f, 258 records with `rrec.length < 3` even read the type or
  length bytes from the simulated region.
- With valid records (`rrec.length <= 16384`), the DTLS `write_length`
  check is redundant once the length check has passed. A test shows this.

## Usage

```sh
PYTHONPATH=src python3 -m heartbeat_model check --length-field 65535 --body-len 0
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/gen_results.py /tmp/out && diff -r results /tmp/out
```

See [SOURCES.md](SOURCES.md), [LIMITATIONS.md](LIMITATIONS.md) and
[PRACTICE.md](PRACTICE.md) (Spanish). A Spanish README is in
[README.es.md](README.es.md).

License: Apache-2.0.
