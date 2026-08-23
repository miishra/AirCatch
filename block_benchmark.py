#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
block_benchmark.py — sweep PERIODIC_BLOCK_S and report a full confusion matrix.

For each block size B in the grid, the per-block gates are scaled to B so that
every block size gets a fair test:

    PERIODIC_BLOCK_S           = B
    PERIODIC_STEP_S            = B               (non-overlapping, matches Aircatch.py's shipped config)
    DUR_MIN                    = DUR_RATIO * B   (the per-block strict gate)
    PERIODIC_MIN_PERSISTENCE_S = B               (the cross-block persistence gate)

Why DUR_RATIO = 1700/2400
-------------------------
Aircatch.py ships PERIODIC_BLOCK_S=2400 with DUR_MIN=1700, i.e. it asks a cluster
to cover 1700/2400 = 70.8% of its block. Holding that ratio fixed reproduces the
shipped calibration exactly at B=2400 and applies the same demand at every other
block size, so block size is the only variable that moves.

DUR_RATIO must stay below 1.0. _strict_decision compares a cluster's within-block
persistence_s (t_end.max - t_start.min over packets falling inside [start, start+B))
against DUR_MIN, and that quantity is strictly less than B -- measured maxima are
597.8s for B=600 and 2337.9s for B=2400. DUR_MIN = B exactly would be unsatisfiable
at every block size, the same floor effect the fixed DUR_MIN=1700 produces for
every B < 1700.

Outputs (in --outdir):
    block_benchmark_per_file.csv  one row per (block, csv), with per-gate diagnostics
    block_benchmark_summary.csv   one row per block: tp/fp/fn/tn + derived rates
"""

import argparse
import os
import sys
import time
import traceback
from pathlib import Path

os.environ.setdefault("MPLBACKEND", "Agg")

import multiprocessing as mp

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


# Default: 10 min .. 60 min in 5-minute steps
BLOCK_GRID = [600, 900, 1200, 1500, 1800, 2100, 2400, 2700, 3000, 3300, 3600]

# Scenario folders under controlled/. Benign supplies most of the true negatives.
SCENARIOS = ["HtoW", "WtoH", "Airport", "Car_Trip", "Benign"]

DUR_RATIO = 1700 / 2400  # 0.70833..., the ratio Aircatch.py's shipped 40-min config uses


def _collect(scenarios: list[str]) -> list[Path]:
    out = []
    for s in scenarios:
        base = HERE / "controlled" / s
        if not base.is_dir():
            print(f"[warn] missing scenario folder: {base}", file=sys.stderr)
            continue
        out.extend(sorted(base.rglob("*.csv")))
    return out


_SKIPPED = None


def _install_empty_block_guard(A):
    """Skip blocks that survive the len()==0 check but filter down to zero segments.

    Aircatch's periodic loop guards `len(adv_b) == 0` but not the case where every
    packet in the block is dropped by the crc_ok / aafe40 / 4c00121900 filters. In
    that case prepare_segments raises RuntimeError and the whole file aborts, which
    disproportionately kills the Benign captures -- i.e. the true negatives. Skipping
    just that block keeps the file scoreable.
    """
    if getattr(A, "_bb_guard_installed", False):
        return
    inner = A._run_one_csv_once

    def guarded(*a, **kw):
        global _SKIPPED
        try:
            return inner(*a, **kw)
        except RuntimeError as e:
            if "No segments produced" not in str(e):
                raise
            if _SKIPPED is not None:
                _SKIPPED[0] += 1
            return pd.DataFrame(), pd.DataFrame(), {}

    A._run_one_csv_once = guarded
    A._bb_guard_installed = True


def _worker(task):
    """Run one CSV under one block size. Must stay top-level for pickling."""
    global _SKIPPED
    csv_path, block_s, dur_ratio, dens_min = task

    import io
    import contextlib

    import Aircatch as A

    _install_empty_block_guard(A)
    _SKIPPED = [0]

    A.PERIODIC_MODE = True
    A.PERIODIC_BLOCK_S = float(block_s)
    A.PERIODIC_STEP_S = float(block_s)
    A.MIN_DURATION_S = float(dur_ratio) * float(block_s)
    A.DUR_MIN = float(dur_ratio) * float(block_s)
    A.PERIODIC_MIN_PERSISTENCE_S = float(block_s)
    if dens_min is not None:
        A.DENSITY_MIN = float(dens_min)

    t0 = time.time()
    row = {
        "block_s": float(block_s),
        "dur_min": float(A.DUR_MIN),
        "persist_min_s": float(A.PERIODIC_MIN_PERSISTENCE_S),
        "dens_min": float(A.DENSITY_MIN),
        "src_file": str(csv_path),
        "scenario": Path(csv_path).relative_to(HERE / "controlled").parts[0],
    }

    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cand_df, summary_df, meta = A._run_one_csv(Path(csv_path))
            raw = pd.read_csv(csv_path)
            hours = A._scenario_hours(raw)
            det = A._compute_detection_metrics(meta, cand_df)
            ttd = A._compute_ttd_seconds(meta)

        max_pers = np.nan
        if summary_df is not None and len(summary_df) and "persistence_s" in summary_df.columns:
            v = pd.to_numeric(summary_df["persistence_s"], errors="coerce")
            if np.isfinite(v).any():
                max_pers = float(np.nanmax(v.values))

        row.update(det)
        row.update({
            "hours": float(hours),
            "ttd_s": float(ttd) if np.isfinite(ttd) else np.nan,
            "n_blocks": int(meta.get("n_blocks", 0) or 0),
            "strict_any": bool(meta.get("strict_any", False)),
            "persist_confirmed": bool(meta.get("persist_confirmed", False)),
            "confirmed_any": bool(meta.get("confirmed_any", False)),
            "max_block_persistence_s": max_pers,
            "gt_adv_mac_count": int(meta.get("gt_adv_mac_count", 0) or 0),
            "skipped_blocks": int(_SKIPPED[0]),
            "error": "",
            "secs": round(time.time() - t0, 1),
        })
    except Exception as e:
        row.update({
            "gt_pos": np.nan, "pred_pos": np.nan,
            "tp": 0, "fp": 0, "fn": 0, "tn": 0,
            "error": f"{type(e).__name__}: {e}",
            "secs": round(time.time() - t0, 1),
        })
        traceback.print_exc(file=sys.stderr)

    return row


def _safe_div(a, b):
    return float(a) / float(b) if b else 0.0


def summarize(per_file: pd.DataFrame) -> pd.DataFrame:
    rows = []
    ok = per_file[per_file["error"] == ""]
    for block_s, g in ok.groupby("block_s"):
        tp = int(g["tp"].sum())
        fp = int(g["fp"].sum())
        fn = int(g["fn"].sum())
        tn = int(g["tn"].sum())

        prec = _safe_div(tp, tp + fp)
        rec = _safe_div(tp, tp + fn)
        spec = _safe_div(tn, tn + fp)
        f1 = _safe_div(2 * prec * rec, prec + rec) if (prec + rec) else 0.0

        ttd = pd.to_numeric(g.loc[g["gt_pos"] == True, "ttd_s"], errors="coerce")  # noqa: E712
        ttd = ttd[np.isfinite(ttd)]

        rows.append({
            "block_s": float(block_s),
            "block_min": round(float(block_s) / 60.0, 1),
            "dur_min": float(g["dur_min"].iloc[0]),
            "persist_min_s": float(g["persist_min_s"].iloc[0]),
            "n_files": int(len(g)),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "specificity": round(spec, 4),
            "f1": round(f1, 4),
            "accuracy": round(_safe_div(tp + tn, tp + tn + fp + fn), 4),
            "balanced_acc": round((rec + spec) / 2.0, 4),
            "fp_per_hour": round(_safe_div(fp, float(g["hours"].sum())), 4),
            "ttd_median_s": round(float(np.median(ttd)), 1) if len(ttd) else np.nan,
            "ttd_p90_s": round(float(np.percentile(ttd, 90)), 1) if len(ttd) else np.nan,
            "skipped_blocks": int(g["skipped_blocks"].fillna(0).sum()),
            "n_errors": int((per_file[per_file["block_s"] == block_s]["error"] != "").sum()),
        })
    return pd.DataFrame(rows).sort_values("block_s").reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser(description="Sweep PERIODIC_BLOCK_S and report TP/FP/FN/TN")
    ap.add_argument("--blocks", default=",".join(str(b) for b in BLOCK_GRID),
                    help="Comma-separated block sizes in seconds")
    ap.add_argument("--scenarios", default=",".join(SCENARIOS),
                    help="Comma-separated scenario folders under controlled/")
    ap.add_argument("--dur-ratio", type=float, default=DUR_RATIO,
                    help="DUR_MIN = ratio * block_s (must be < 1.0; see module docstring)")
    ap.add_argument("--density-min", type=float, default=None,
                    help="Override DENSITY_MIN (default: whatever Aircatch.py defines)")
    ap.add_argument("--workers", type=int, default=min(20, mp.cpu_count()))
    ap.add_argument("--limit", type=int, default=0, help="Smoke test: use only the first N CSVs")
    ap.add_argument("--outdir", default="block_benchmark_out")
    args = ap.parse_args()

    if args.dur_ratio >= 1.0:
        print(f"[warn] --dur-ratio {args.dur_ratio} >= 1.0 makes the strict gate unsatisfiable "
              f"at every block size; recall will be 0 by construction.", file=sys.stderr)

    blocks = [float(x) for x in args.blocks.split(",") if x.strip()]
    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]

    csvs = _collect(scenarios)
    if args.limit:
        csvs = csvs[: args.limit]
    if not csvs:
        raise SystemExit("No CSVs found.")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    tasks = [(str(p), b, args.dur_ratio, args.density_min)
             for b in blocks for p in csvs]

    print(f"[bench] {len(csvs)} csvs x {len(blocks)} blocks = {len(tasks)} runs "
          f"on {args.workers} workers", flush=True)
    print(f"[bench] blocks={[int(b) for b in blocks]}", flush=True)
    print(f"[bench] dur_ratio={args.dur_ratio:.5f}  persist_min_s=block_s", flush=True)

    t0 = time.time()
    rows = []
    with mp.Pool(processes=args.workers) as pool:
        for i, r in enumerate(pool.imap_unordered(_worker, tasks, chunksize=1), 1):
            rows.append(r)
            if i % 25 == 0 or i == len(tasks):
                el = time.time() - t0
                eta = el / i * (len(tasks) - i)
                print(f"[bench] {i}/{len(tasks)} elapsed={el/60:.1f}m eta={eta/60:.1f}m", flush=True)

    per_file = pd.DataFrame(rows).sort_values(["block_s", "src_file"]).reset_index(drop=True)
    per_file_path = outdir / "block_benchmark_per_file.csv"
    per_file.to_csv(per_file_path, index=False)

    summary = summarize(per_file)
    summary_path = outdir / "block_benchmark_summary.csv"
    summary.to_csv(summary_path, index=False)

    print()
    cols = ["block_min", "dur_min", "tp", "fp", "fn", "tn", "precision", "recall",
            "specificity", "f1", "balanced_acc", "ttd_median_s"]
    print(summary[cols].to_string(index=False))
    print()

    n_err = int((per_file["error"] != "").sum())
    if n_err:
        print(f"[bench] {n_err} runs errored; see the 'error' column in {per_file_path}")
    print(f"[bench] wrote {per_file_path}")
    print(f"[bench] wrote {summary_path}")
    print(f"[bench] total {(time.time() - t0)/60:.1f} min")


if __name__ == "__main__":
    main()
