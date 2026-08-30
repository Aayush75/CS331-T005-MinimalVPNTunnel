#!/usr/bin/env python3
"""Summarize packet-size / RTT / load / UDP-rate experiment directories."""

from __future__ import annotations

import csv
import json
import math
import pathlib
import re
import statistics
import sys

MODES = ("direct", "plaintext", "encrypted")


def mean_std(xs: list[float]) -> tuple[float, float]:
    xs = [x for x in xs if not math.isnan(x)]
    if not xs:
        return (float("nan"), float("nan"))
    if len(xs) == 1:
        return (xs[0], 0.0)
    return (statistics.mean(xs), statistics.stdev(xs))


def fmt(mu: float, sd: float, digits: int = 2) -> str:
    if math.isnan(mu):
        return "n/a"
    return f"{mu:.{digits}f} ± {sd:.{digits}f}"


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


def read_udp_iperf(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text())
    end = data.get("end") or {}
    server = (data.get("server_output_json") or {}).get("end") or {}
    send = end.get("sum_sent") or end.get("sum") or {}
    recv = (
        end.get("sum_received")
        or server.get("sum")
        or end.get("sum")
        or {}
    )
    start = data.get("start") or {}
    test = start.get("test_start") or {}
    payload = int(test.get("blksize") or 0)
    duration = float(recv.get("seconds") or send.get("seconds") or 0.0)
    recv_bps = float(recv.get("bits_per_second") or 0.0)
    send_bps = float(send.get("bits_per_second") or 0.0)
    lost_pct = float(recv.get("lost_percent") if recv.get("lost_percent") is not None else float("nan"))
    jitter = float(recv.get("jitter_ms") if recv.get("jitter_ms") is not None else float("nan"))
    lost_pkts = int(recv.get("lost_packets") or 0)
    packets = int(recv.get("packets") or 0)
    rx_packets = max(packets - lost_pkts, 0)
    pps = rx_packets / duration if duration > 0 else float("nan")
    return {
        "recv_mbps": recv_bps / 1e6,
        "send_mbps": send_bps / 1e6,
        "lost_percent": lost_pct,
        "jitter_ms": jitter,
        "lost_packets": lost_pkts,
        "packets": packets,
        "pps": pps,
        "payload": payload,
        "duration": duration,
    }


def parse_ping(path: pathlib.Path) -> dict:
    text = path.read_text(errors="replace") if path.is_file() else ""
    out = {
        "tx": float("nan"),
        "rx": float("nan"),
        "loss_percent": float("nan"),
        "rtt_min": float("nan"),
        "rtt_avg": float("nan"),
        "rtt_max": float("nan"),
        "rtt_mdev": float("nan"),
        "exit": float("nan"),
        "too_long": "Message too long" in text or "Frag needed" in text or "mtu" in text.lower() and "do" in text.lower(),
    }
    m = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received,(?:\s+\+\d+ errors,)?\s+([0-9.]+)%\s+packet loss",
        text,
    )
    if m:
        out["tx"] = float(m.group(1))
        out["rx"] = float(m.group(2))
        out["loss_percent"] = float(m.group(3))
    m = re.search(
        r"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms",
        text,
    )
    if m:
        out["rtt_min"] = float(m.group(1))
        out["rtt_avg"] = float(m.group(2))
        out["rtt_max"] = float(m.group(3))
        out["rtt_mdev"] = float(m.group(4))
    m = re.search(r"^exit=(\d+)", text, re.M)
    if m:
        out["exit"] = float(m.group(1))
    return out


def cpu_pair(d: pathlib.Path, run: int) -> tuple[float | None, float | None]:
    return (
        read_pidstat_avg_cpu(d / f"run{run}_pidstat_a.txt"),
        read_pidstat_avg_cpu(d / f"run{run}_pidstat_b.txt"),
    )


def collect_udp(root: pathlib.Path, rel: str) -> list[dict]:
    rows = []
    base = root / rel
    if not base.is_dir():
        return rows
    for iperf in sorted(base.rglob("run*_iperf.json")):
        parts = iperf.relative_to(base).parts
        # .../{dir}/{size}/{mode}/runN  or  .../{dir}/{size}/{rate}/{mode}/runN
        try:
            stats = read_udp_iperf(iperf)
        except (json.JSONDecodeError, OSError):
            continue
        m = re.search(r"run(\d+)_iperf", iperf.name)
        run = int(m.group(1)) if m else 0
        mode = parts[-2]
        if mode not in MODES:
            continue
        ca, cb = cpu_pair(iperf.parent, run)
        row = {
            "path": str(iperf.relative_to(root)),
            "direction": parts[0],
            "size": parts[1],
            "mode": mode,
            "run": run,
            "recv_mbps": stats["recv_mbps"],
            "send_mbps": stats["send_mbps"],
            "lost_percent": stats["lost_percent"],
            "jitter_ms": stats["jitter_ms"],
            "pps": stats["pps"],
            "packets": stats["packets"],
            "cpu_a": ca,
            "cpu_b": cb,
        }
        if len(parts) >= 4 and parts[2] not in MODES:
            row["rate"] = parts[2]
        rows.append(row)
    return rows


def collect_ping(root: pathlib.Path) -> list[dict]:
    rows = []
    base = root / "test2_ping"
    if not base.is_dir():
        return rows
    for pingf in sorted(base.rglob("run*_ping.txt")):
        parts = pingf.relative_to(base).parts
        stats = parse_ping(pingf)
        rows.append(
            {
                "direction": parts[0],
                "size": parts[1],
                "mode": parts[2],
                **{k: stats[k] for k in ("rtt_avg", "rtt_min", "rtt_max", "rtt_mdev", "loss_percent")},
            }
        )
    return rows


def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return out


def write_csv(path: pathlib.Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            out = {}
            for k in fields:
                v = row.get(k, "")
                if isinstance(v, float):
                    out[k] = "" if math.isnan(v) else f"{v:.6f}"
                elif v is None:
                    out[k] = ""
                else:
                    out[k] = v
            w.writerow(out)


def group_udp(rows: list[dict], keys: tuple[str, ...]) -> dict[tuple, dict]:
    grouped: dict[tuple, dict] = {}
    buckets: dict[tuple, list[dict]] = {}
    for row in rows:
        k = tuple(str(row[x]) for x in keys)
        buckets.setdefault(k, []).append(row)
    for k, items in buckets.items():
        def col(name: str) -> list[float]:
            xs = []
            for it in items:
                v = it.get(name)
                if v is None:
                    continue
                if isinstance(v, float) and math.isnan(v):
                    continue
                xs.append(float(v))
            return xs

        grouped[k] = {
            "send": mean_std(col("send_mbps")),
            "recv": mean_std(col("recv_mbps")),
            "loss": mean_std(col("lost_percent")),
            "jitter": mean_std(col("jitter_ms")),
            "pps": mean_std(col("pps")),
            "cpu_a": mean_std(col("cpu_a")),
            "cpu_b": mean_std(col("cpu_b")),
            "n": len(items),
        }
    return grouped


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: summarize_packet_experiments.py results/<timestamp>-packet", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    md: list[str] = [f"# Packet experiments ({root.name})", ""]
    md.append("Complementary to bulk TCP. Interleaved **direct → plaintext → encrypted**.")
    md.append("Do not treat direct-vs-encrypted as encryption overhead.")
    md.append("")

    t1 = collect_udp(root, "test1_udp_size")
    t1b = collect_udp(root, "test1_udp_max")
    t4 = collect_udp(root, "test4_udp_rate")
    pings = collect_ping(root)

    write_csv(
        root / "test1_udp_size.csv",
        t1,
        ["direction", "size", "mode", "run", "recv_mbps", "send_mbps", "lost_percent", "jitter_ms", "pps", "cpu_a", "cpu_b"],
    )
    write_csv(
        root / "test1_udp_max.csv",
        t1b,
        ["direction", "size", "mode", "run", "recv_mbps", "send_mbps", "lost_percent", "jitter_ms", "pps", "cpu_a", "cpu_b"],
    )
    write_csv(
        root / "test2_ping.csv",
        pings,
        ["direction", "size", "mode", "rtt_avg", "rtt_min", "rtt_max", "rtt_mdev", "loss_percent"],
    )
    write_csv(
        root / "test4_udp_rate.csv",
        t4,
        ["direction", "size", "rate", "mode", "run", "recv_mbps", "lost_percent", "jitter_ms", "pps", "cpu_a", "cpu_b"],
    )

    md.append("## Test 1 — UDP goodput vs datagram size (fixed 20 Mbps offer)")
    md.append("")
    md.append("iperf3 `-u -b 20M -l SIZE`. **Recv Mbps is `sum_received` goodput**, not the offered `-b` rate.")
    md.append("")
    g1 = group_udp(t1, ("direction", "size", "mode"))
    sizes = sorted({r["size"] for r in t1}, key=lambda s: int(s) if str(s).isdigit() else 0)
    dirs = sorted({r["direction"] for r in t1})
    for direction in dirs:
        md.append(f"### {direction}")
        md.append("")
        rows = []
        for size in sizes:
            for mode in MODES:
                g = g1.get((direction, size, mode))
                if not g:
                    rows.append([size, mode, "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"])
                    continue
                rows.append(
                    [
                        size,
                        mode,
                        fmt(*g["send"]),
                        fmt(*g["recv"]),
                        fmt(*g["loss"]),
                        fmt(*g["pps"], 0),
                        fmt(*g["cpu_a"]),
                        fmt(*g["cpu_b"]),
                    ]
                )
        md.extend(md_table(["Size", "Mode", "Send Mbps", "Recv Mbps", "Loss %", "rx pps", "CPU A %", "CPU B %"], rows))
        md.append("")

    md.append("## Test 1b — UDP max-effort at 64 and 1372 (A→B, `-b 100M`)")
    md.append("")
    g1b = group_udp(t1b, ("direction", "size", "mode"))
    rows = []
    for size in sorted({r["size"] for r in t1b}, key=lambda s: int(s) if str(s).isdigit() else 0):
        for mode in MODES:
            g = g1b.get(("a_to_b", size, mode))
            if not g:
                continue
            rows.append(
                [
                    size,
                    mode,
                    fmt(*g["send"]),
                    fmt(*g["recv"]),
                    fmt(*g["loss"]),
                    fmt(*g["pps"], 0),
                    fmt(*g["cpu_a"]),
                    fmt(*g["cpu_b"]),
                ]
            )
    if rows:
        md.extend(md_table(["Size", "Mode", "Send Mbps", "Recv Mbps", "Loss %", "rx pps", "CPU A %", "CPU B %"], rows))
    else:
        md.append("No max-effort rows.")
    md.append("")

    md.append("## Test 2 — ping RTT vs ICMP payload")
    md.append("")
    ping_sizes = sorted({r["size"] for r in pings}, key=lambda s: int(s) if str(s).isdigit() else 0)
    rows = []
    for size in ping_sizes:
        for mode in MODES:
            matches = [r for r in pings if r["size"] == size and r["mode"] == mode]
            if not matches:
                continue
            rtt = mean_std([r["rtt_avg"] for r in matches])
            loss = mean_std([r["loss_percent"] for r in matches])
            rows.append([size, mode, fmt(*rtt), fmt(*loss)])
    if rows:
        md.extend(md_table(["Payload -s", "Mode", "RTT avg ms", "Loss %"], rows))
    else:
        md.append("No ping rows.")
    md.append("")
    md.append("`-s 0` replies had no `time=` / rtt summary on this iputils build, so RTT is n/a. Loss was still 0%.")
    md.append("")

    md.append("### DF oversize (`ping -M do -s 1400`)")
    md.append("")
    df_rows = []
    for mode in MODES:
        p = root / "test2_ping_df" / mode / "run1_ping.txt"
        stats = parse_ping(p)
        note = "too long / DF fail" if stats["too_long"] or (not math.isnan(stats["exit"]) and stats["exit"] != 0) else "unexpected success"
        if p.is_file() and "Message too long" in p.read_text(errors="replace"):
            note = "Message too long (expected on TUN MTU 1400)"
        elif p.is_file() and not math.isnan(stats["loss_percent"]) and stats["loss_percent"] >= 99:
            note = "100% loss / no replies (path MTU)"
        df_rows.append(
            [
                mode,
                "n/a" if math.isnan(stats["loss_percent"]) else f"{stats['loss_percent']:.0f}",
                "n/a" if math.isnan(stats["exit"]) else str(int(stats["exit"])),
                note,
            ]
        )
    md.extend(md_table(["Mode", "Loss %", "exit", "Note"], df_rows))
    md.append("")
    md.append("ICMP payload 1400 plus IP/ICMP headers exceeds TUN MTU 1400, so DF should fail on tunnel modes.")
    md.append("")

    md.append("## Test 3 — idle RTT vs RTT during TCP load (A→B)")
    md.append("")
    t3_rows = []
    t3_csv = []
    load_base = root / "test3_load" / "a_to_b"
    for mode in MODES:
        d = load_base / mode
        if not d.is_dir():
            continue
        idle_avgs = []
        load_avgs = []
        idle_loss = []
        load_loss = []
        tcp_mbps = []
        for idle in sorted(d.glob("run*_ping_idle.txt")):
            m = re.search(r"run(\d+)_", idle.name)
            run = int(m.group(1)) if m else 0
            i = parse_ping(idle)
            l = parse_ping(d / f"run{run}_ping_load.txt")
            idle_avgs.append(i["rtt_avg"])
            load_avgs.append(l["rtt_avg"])
            idle_loss.append(i["loss_percent"])
            load_loss.append(l["loss_percent"])
            iperf = d / f"run{run}_iperf.json"
            tcp = float("nan")
            if iperf.is_file():
                try:
                    data = json.loads(iperf.read_text())
                    end = data.get("end") or {}
                    sent = end.get("sum_sent") or end.get("sum") or {}
                    tcp = float(sent.get("bits_per_second") or 0.0) / 1e6
                    tcp_mbps.append(tcp)
                except (json.JSONDecodeError, OSError):
                    pass
            t3_csv.append(
                {
                    "mode": mode,
                    "run": run,
                    "idle_rtt": i["rtt_avg"],
                    "load_rtt": l["rtt_avg"],
                    "idle_loss": i["loss_percent"],
                    "load_loss": l["loss_percent"],
                    "tcp_mbps": tcp,
                }
            )
        di = mean_std(idle_avgs)
        dl = mean_std(load_avgs)
        delta = dl[0] - di[0] if not (math.isnan(dl[0]) or math.isnan(di[0])) else float("nan")
        t3_rows.append(
            [
                mode,
                fmt(*di),
                fmt(*dl),
                "n/a" if math.isnan(delta) else f"{delta:.2f}",
                fmt(*mean_std(tcp_mbps)),
                fmt(*mean_std(idle_loss)),
                fmt(*mean_std(load_loss)),
            ]
        )
    write_csv(
        root / "test3_load.csv",
        t3_csv,
        ["mode", "run", "idle_rtt", "load_rtt", "idle_loss", "load_loss", "tcp_mbps"],
    )
    if t3_rows:
        md.extend(
            md_table(
                ["Mode", "Idle RTT ms", "Loaded RTT ms", "Δ ms", "TCP Mbps", "Idle loss %", "Load loss %"],
                t3_rows,
            )
        )
    else:
        md.append("No load rows.")
    md.append("")
    md.append("If extra work is only AEAD, encrypted loaded RTT should stay close to plaintext loaded RTT.")
    md.append("")

    md.append("## Test 4 — UDP loss vs offered rate (A→B)")
    md.append("")
    g4 = group_udp(t4, ("size", "rate", "mode"))
    rate_order = ["5M", "10M", "20M", "40M", "80M"]
    for size in ("64", "1372"):
        md.append(f"### payload {size}")
        md.append("")
        rows = []
        for rate in rate_order:
            for mode in MODES:
                g = g4.get((size, rate, mode))
                if not g:
                    continue
                rows.append(
                    [
                        rate,
                        mode,
                        fmt(*g["send"]),
                        fmt(*g["recv"]),
                        fmt(*g["loss"]),
                        fmt(*g["pps"], 0),
                        fmt(*g["cpu_a"]),
                        fmt(*g["cpu_b"]),
                    ]
                )
        if rows:
            md.extend(md_table(["Offer", "Mode", "Send Mbps", "Recv Mbps", "Loss %", "rx pps", "CPU A %", "CPU B %"], rows))
        else:
            md.append("No rows.")
        md.append("")

    md.append("## How to read these")
    md.append("")
    md.append("- Small UDP datagrams raise packets/s; per-packet TUN, poll, and AEAD cost show up as CPU and loss, not as a large Mbps gap.")
    md.append("- Bulk TCP remains the headline goodput number. These tests isolate packet-rate and latency behaviour.")
    md.append("- Wi-Fi contention can move all three modes together.")
    md.append("")

    (root / "summary.md").write_text("\n".join(md) + "\n")
    print(f"wrote {root / 'summary.md'}")
    for name in ("test1_udp_size.csv", "test1_udp_max.csv", "test2_ping.csv", "test3_load.csv", "test4_udp_rate.csv"):
        print(f"wrote {root / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
