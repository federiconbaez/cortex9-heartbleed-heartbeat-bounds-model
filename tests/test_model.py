import json
import pathlib
import unittest

from heartbeat_model.heartbeat import IMPLS, VERSIONS, leaked, process, record
from heartbeat_model.sweep import sweep

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Fixtures(unittest.TestCase):
    def test_cases(self):
        data = json.loads((ROOT / "fixtures/cases.json").read_text())
        for c in data["cases"]:
            rec = record(c["type"], c["field"], b"\x42" * c["body_len"])
            impls = [c["impl"]] if "impl" in c else list(IMPLS)
            for impl in impls:
                for v, exp in c["expect"].items():
                    r = process(v, impl, rec)
                    with self.subTest(id=c["id"], v=v, impl=impl):
                        self.assertEqual(r["action"], exp["action"])
                        self.assertEqual(leaked(r), exp["leak"])


class Properties(unittest.TestCase):
    def test_closed_form_leak_pre(self):
        # independent of the model's byte tracking: arithmetic on lengths only
        for total in range(3, 60):
            for field in (0, 1, 15, 16, 17, 40, 300):
                rec = record(1, field, b"\x00" * (total - 3))
                r = process("1.0.1f", "tls", rec)
                self.assertEqual(leaked(r), max(0, field - (total - 3)))

    def test_post_respond_iff_bound(self):
        for total in range(0, 60):
            for field in (0, 1, 2, 16, 40, 41, 65535):
                rec = record(1, field, b"\x00" * max(0, total - 3))[:total]
                r = process("1.0.1g", "tls", rec)
                ok = total >= 19 and 3 + field + 16 <= total
                self.assertEqual(r["action"] == "RESPOND", ok, (total, field))

    def test_sweep_invariant(self):
        s = sweep()
        for impl in IMPLS:
            self.assertGreater(s[("1.0.1f", impl)]["leaking_records"], 0)
            self.assertEqual(s[("1.0.1g", impl)]["simulated_bytes_echoed"], 0)
            self.assertEqual(s[("1.0.1g", impl)]["simulated_header_reads"], 0)

    def test_dtls_write_check_unreachable_for_valid_records(self):
        # after the length check payload <= rrec.length - 19, so write_length <= rrec.length
        for total in (19, 1000, 16383, 16384):
            for field in range(max(0, total - 22), total - 18):
                r = process("1.0.1g", "dtls", record(1, field, b"\x00" * (total - 3)))
                self.assertNotEqual(r.get("reason"), "write_length > SSL3_RT_MAX_PLAIN_LENGTH")

    def test_simulated_region_is_synthetic(self):
        r = process("1.0.1f", "tls", record(1, 4, b""))
        self.assertEqual(r["first_simulated_offset"], 3)
        self.assertEqual(set(VERSIONS), {"1.0.1f", "1.0.1g"})


if __name__ == "__main__":
    unittest.main()
