#!/usr/bin/env python3
"""Summarize iperf3 JSON + pidstat logs for one results/<timestamp>/ directory."""

from __future__ import annotations

import csv
import json
import math
import pathlib
import re
import statistics
import sys

MODES = ("direct", "plaintext", "encrypted")
DIRS = ("a_to_b", "b_to_a")


def mean_std(xs: list[float]) -> tuple[float, float]:
    if not xs:
        return (float("nan"), float("nan"))
    if len(xs) == 1:
        return (xs[0], 0.0)
    return (statistics.mean(xs), statistics.stdev(xs))


def bps_to_mbps(bps: float) -> float:
    return bps / 1e6


def read_iperf(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text())
    end = data.get("end", {})
    sent = end.get("sum_sent") or end.get("sum") or {}
    recv = end.get("sum_received") or {}
    return {
        "sent_bps": float(sent.get("bits_per_second") or 0.0),
        "recv_bps": float(recv.get("bits_per_second") or sent.get("bits_per_second") or 0.0),
        "retrans": int(sent.get("retransmits") or 0),
    }


def read_pidstat_avg_cpu(path: pathlib.Path) -> float | None:
    if not path.is_file():
        return None
    cpus: list[float] = []
    cpu_idx = None
    for line in path.read_text(errors="replace").splitlines():
        if "%CPU" in line and "Command" in line:
            cols = line.split()
            try:
                cpu_idx = cols.index("%CPU")
            except ValueError:
                cpu_idx = None
            continue
        if cpu_idx is None:
            continue
        if not line.strip() or line.startswith("Linux") or line.startswith("Average"):
            continue
        cols = line.split()
        if len(cols) <= cpu_idx:
            continue
        try:
            cpus.append(float(cols[cpu_idx]))
        except ValueError:
            continue
    if not cpus:
        return None
    return statistics.mean(cpus)


def fmt(mu: float, sd: float) -> str:
    if math.isnan(mu):
        return "n/a"
    return f"{mu:.2f} ± {sd:.2f}"


def overhead(a: float, b: float) -> float:
    if a == 0 or math.isnan(a) or math.isnan(b):
        return float("nan")
    return (a - b) / a * 100.0


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: summarize_results.py results/<timestamp>", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    rows = []
    grouped: dict[tuple[str, str], dict] = {}

    for mode in MODES:
        for direction in DIRS:
            d = root / mode / direction
            throughputs = []
            recvs = []
            retrs = []
            cpu_a = []
            cpu_b = []
            for iperf in sorted(d.glob("run*_iperf.json")):
                m = re.search(r"run(\d+)_iperf", iperf.name)
                run = int(m.group(1)) if m else 0
                stats = read_iperf(iperf)
                t_send = bps_to_mbps(stats["sent_bps"])
                t_recv = bps_to_mbps(stats["recv_bps"])
                throughputs.append(t_send)
                recvs.append(t_recv)
                retrs.append(stats["retrans"])
                ca = read_pidstat_avg_cpu(d / f"run{run}_pidstat_a.txt")
                cb = read_pidstat_avg_cpu(d / f"run{run}_pidstat_b.txt")
                if ca is not None:
                    cpu_a.append(ca)
                if cb is not None:
                    cpu_b.append(cb)
                rows.append(
                    {
                        "mode": mode,
                        "direction": direction,
                        "run": run,
                        "sender_mbps": f"{t_send:.4f}",
                        "receiver_mbps": f"{t_recv:.4f}",
                        "retransmits": stats["retrans"],
                        "cpu_a": "" if ca is None else f"{ca:.3f}",
                        "cpu_b": "" if cb is None else f"{cb:.3f}",
                    }
                )
            grouped[(mode, direction)] = {
                "tput": mean_std(throughputs),
                "recv": mean_std(recvs),
                "cpu_a": mean_std(cpu_a) if cpu_a else (float("nan"), float("nan")),
                "cpu_b": mean_std(cpu_b) if cpu_b else (float("nan"), float("nan")),
            }

    csv_path = root / "summary.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "mode",
                "direction",
                "run",
                "sender_mbps",
                "receiver_mbps",
                "retransmits",
                "cpu_a",
                "cpu_b",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    md = []
    md.append(f"# Benchmark summary ({root.name})")
    md.append("")
    md.append("Throughput is TCP iperf3 sender Mbps. Values are mean ± sample standard deviation.")
    md.append("")
    md.append("| Mode | Direction | Throughput Mbps | Receiver Mbps | svpn CPU A % | svpn CPU B % |")
    md.append("|---|---|---|---|---|---|")
    for mode in MODES:
        for direction in DIRS:
            g = grouped[(mode, direction)]
            md.append(
                "| {mode} | {direction} | {t} | {r} | {ca} | {cb} |".format(
                    mode=mode,
                    direction=direction,
                    t=fmt(*g["tput"]),
                    r=fmt(*g["recv"]),
                    ca=fmt(*g["cpu_a"]),
                    cb=fmt(*g["cpu_b"]),
                )
            )
    md.append("")
    md.append("## Overhead (do not call direct-vs-encrypted 'encryption overhead')")
    md.append("")
    md.append("| Direction | Tunnel overhead % `(direct-plaintext)/direct` | Incremental crypto % `(plaintext-encrypted)/plaintext` | Total VPN % `(direct-encrypted)/direct` |")
    md.append("|---|---|---|---|")
    for direction in DIRS:
        d_mu = grouped[("direct", direction)]["tput"][0]
        p_mu = grouped[("plaintext", direction)]["tput"][0]
        e_mu = grouped[("encrypted", direction)]["tput"][0]
        md.append(
            "| {d} | {t:.2f} | {c:.2f} | {v:.2f} |".format(
                d=direction,
                t=overhead(d_mu, p_mu),
                c=overhead(p_mu, e_mu),
                v=overhead(d_mu, e_mu),
            )
        )
    md.append("")
    md.append("## Incremental crypto CPU (`encrypted - plaintext`)")
    md.append("")
    md.append("| Direction | Δ CPU A (pp) | Δ CPU B (pp) |")
    md.append("|---|---|---|")
    for direction in DIRS:
        pa, _ = grouped[("plaintext", direction)]["cpu_a"]
        ea, _ = grouped[("encrypted", direction)]["cpu_a"]
        pb, _ = grouped[("plaintext", direction)]["cpu_b"]
        eb, _ = grouped[("encrypted", direction)]["cpu_b"]
        da = ea - pa if not (math.isnan(ea) or math.isnan(pa)) else float("nan")
        db = eb - pb if not (math.isnan(eb) or math.isnan(pb)) else float("nan")
        md.append(f"| {direction} | {da:.2f} | {db:.2f} |")
    md.append("")
    md.append("Direct mode has no `svpn` process, so VPN-process CPU is not compared against Wi-Fi baseline.")
    md.append("Wi-Fi contention can dominate all three modes; interpret overheads with that in mind.")
    md.append("")

    live = False
    sticky = False
    for p in root.rglob("*therm*.txt"):
        text = p.read_text(errors="replace")
        if "throttled=" not in text:
            continue
        m = re.search(r"throttled=(0x[0-9a-fA-F]+)", text)
        if not m:
            continue
        val = int(m.group(1), 16)
        if val & 0xF:
            live = True
            throttle_notes.append(f"- LIVE `{p.relative_to(root)}`: {text.strip().replace(chr(10), ' | ')}")
        elif val:
            sticky = True
    if live or sticky:
        md.append("## Thermal / throttle notes")
        md.append("")
        if sticky and not live:
            md.append("Sticky `get_throttled` bits (e.g. `0x50000`) were set: under-voltage or throttling happened earlier, not necessarily during these runs. Temperatures stayed around 43–47 °C.")
            md.append("")
        if live:
            md.append("**Live throttling was detected during measurements. Cool the Pis and re-run before treating numbers as final.**")
            md.append("")
            md.extend(throttle_notes[:20])
            md.append("")

    (root / "summary.md").write_text("\n".join(md) + "\n")
    print(f"wrote {csv_path}")
    print(f"wrote {root / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
