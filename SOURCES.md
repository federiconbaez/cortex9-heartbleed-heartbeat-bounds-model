# Sources

All files were fetched once and read offline. The SHA-256 hashes are of
the local copies.

| File | Origin | SHA-256 |
|---|---|---|
| openssl-96db9023.diff | https://github.com/openssl/openssl/commit/96db9023b881d7cd9f379b0c154650d6c108e9a3.diff | f25663ddb215df4b66a0f5d5d292ddb42775cad5fe39659c63b8c083a0ba23ec |
| ssl/t1_lib.c @ 0d7717fc (parent) | https://raw.githubusercontent.com/openssl/openssl/0d7717fc9c83dafab8153cbd5e2180e6e04cc802/ssl/t1_lib.c | 0aa8db1155e3162d081bb37d28f4f7db9480361bd2837ce1880c82acef84289d |
| ssl/t1_lib.c @ 96db9023 | same path at the fix | ea7a9c65d64027c4397633a58b26fb8900bb71cd2252bfb65f42b2ba4b598b0d |
| ssl/d1_both.c @ 0d7717fc | same | 215e28d3a4900b674b4408c13a6c224639b344fcab59f8b89f1f284736f60560 |
| ssl/d1_both.c @ 96db9023 | same | 8748353d8ddf3e92ee49625c61aadd06be31d90f1bf6c08ca08da6350b9ff91f |
| NVD CVE-2014-0160 JSON | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-0160 | 1289c508873ef6a01dca3c6817200f2bb45bed6af5ac6cd9b3749039fa5d0bad |

## Source-to-model trace

| Source line | Model |
|---|---|
| t1_lib.c 0d7717fc l.2589, `unsigned int padding = 16` | `PADDING` |
| l.2592-2594, `hbtype = *p++; n2s(p, payload); pl = p;` | header reads through `SimulatedArena.at` |
| l.2616, `memcpy(bp, pl, payload)` | the `echoed` list |
| t1_lib.c 96db9023 l.2597 and l.2601 | the two `DISCARD` branches |
| d1_both.c 96db9023 l.1484, `write_length > SSL3_RT_MAX_PLAIN_LENGTH` | DTLS-only `DISCARD` |
| TLS1_HB_RESPONSE branch (t1_lib.c l.2633 / l.2637) | `NO_RESPONSE` |

Exploit-database links in the NVD record were not fetched or used.
