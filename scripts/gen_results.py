"""Regenerate results/ (deterministic)."""
import csv
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from heartbeat_model.heartbeat import IMPLS, VERSIONS, leaked, process, record  # noqa: E402
from heartbeat_model.sweep import sweep  # noqa: E402

out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results"
out.mkdir(parents=True, exist_ok=True)
data = json.loads((ROOT / "fixtures/cases.json").read_text())
with open(out / "cases.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["id", "impl", "version", "rrec_length", "payload", "action", "reason", "leak"])
    for c in data["cases"]:
        rec = record(c["type"], c["field"], b"\x42" * c["body_len"])
        for impl in ([c["impl"]] if "impl" in c else IMPLS):
            for v in VERSIONS:
                r = process(v, impl, rec)
                w.writerow([c["id"], impl, v, r["rrec_length"], r.get("payload", ""),
                            r["action"], r.get("reason", ""), leaked(r)])
s = sweep()
with open(out / "sweep_summary.csv", "w", newline="") as f:
    keys = ["records", "respond", "discard", "leaking_records", "simulated_bytes_echoed",
            "max_leak", "simulated_header_reads", "echoed_padding_records"]
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["version", "impl"] + keys)
    for (v, impl), row in sorted(s.items()):
        w.writerow([v, impl] + [row[k] for k in keys])
FILES = ("cases.csv", "sweep_summary.csv")
(out / "SHA256SUMS").write_text("".join(
    f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in FILES))
