#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plot_cfo_figures.py — regenerate the paper's CFO-fingerprint figures from the
shipped captures in dataset/.

    Figure 2a  USRP B210 (SDR): per-device CFO distributions for commodity tags
    Figure 2b  USRP B210 (SDR): CFO over time (four 15-minute windows), one
               representative tag per ecosystem
    Figure 3a  BlePhasyr (EFR32MG24): per-device CFO distributions
    Figure 3b  BlePhasyr: CFO of the four ESP32-based adversary trackers
    Figure 5   per-device transition CFOs (00 / 01 / 10 / 11)

These were previously only available as pre-rendered PDFs: the helper that drew
them (`save_violin_cfo_for_all_devices`) is referenced but never defined in the
shipped `scenario_gen.py`, and the transition-CFO plotter is absent entirely.
This module reimplements them against the captures that DO ship, reusing the
device-labelling and violin styling of `plot_prior_baseline_cfo.py` (which is
verified to reproduce Figure 4 exactly).

Usage:
    python3 plot_cfo_figures.py [output_dir]
"""

import os
import shutil
import sys
from typing import Dict, List, Optional, Sequence, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch
from scipy.stats import gaussian_kde

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "dataset")

SDR_CSV = os.path.join(DATASET, "sdr_b210_static_devices.csv")
BLEPHASYR_CSV = os.path.join(DATASET, "blephasyr_static_devices.csv")
ADVERSARY_CSV = os.path.join(DATASET, "car_trip_final.csv")

# Adversary payload markers, in the paper's Adversary 1..4 order.
ADV_TAGS = ["4c001219ff", "4c001219fc", "4c001219fd", "4c001219fe"]

ECOSYSTEMS = ["APPLE", "GOOGLE", "SAMSUNG", "TILE"]
# Devices kept per ecosystem, matching the paper's panels.
MAX_PER_TYPE = {"APPLE": 15, "GOOGLE": 7, "SAMSUNG": 4, "TILE": 4}

MIN_SAMPLES = 6         # a device needs this many packets to be drawn
VIOLIN_WIDTH = 0.8
USENIX_2COL_WIDTH = 7.0
# Per-device percentile trim. A handful of outlier packets otherwise stretch each
# violin ~3x (median extent 32.9 kHz raw vs 10.0 kHz trimmed) and blow the y-axis
# out to -75..+50 kHz; trimming reproduces the paper's -42..+32 kHz axis.
TRIM_LO, TRIM_HI = 1.0, 99.0
# Figure 3b: packets averaged per accumulated CFO estimate. The adversaries use a
# fresh pseudonym per transmission, so single packets are noisy; averaging 10
# reproduces the paper's ~15 kHz blob width (raw is ~45 kHz).
ACCUM_PKTS = 10
# Figure 2b representatives. scenario_gen's drift plotter keeps the alphabetically
# first identity per ecosystem; the paper's panel uses the first for Apple/Google/
# Tile but the *third* Samsung PRIVID (f9028bfe1e2f4130, per-window medians
# -8.7/-5.3/-4.9/+3.2 -- the published values). Indices are into the same sorted
# identity list the plotter builds.
FIG2B_REP_INDEX = {"APPLE": 0, "GOOGLE": 0, "SAMSUNG": 2, "TILE": 0}


def get_device_color(device_type: str) -> Tuple[str, str]:
    """(face, edge) colour per ecosystem — same palette as plot_prior_baseline_cfo."""
    colors = {
        "APPLE": ("#3b82f6", "#1e40af"),
        "GOOGLE": ("#10b981", "#047857"),
        "SAMSUNG": ("#8b5cf6", "#5b21b6"),
        "TILE": ("#f59e0b", "#b45309"),
    }
    return colors.get(str(device_type).upper(), ("#6b7280", "#374151"))


# --------------------------------------------------------------------------- #
# Loading / labelling
# --------------------------------------------------------------------------- #
def _ecosystem_column(df: pd.DataFrame) -> pd.Series:
    """Use tag_type when the capture carries it, else classify from the payload."""
    if "tag_type" in df.columns and df["tag_type"].notna().any():
        return df["tag_type"].astype(str).str.upper()
    from scenario_gen import classify_tag_ecosystem_from_payload
    payload = df["payload"].astype(str)
    # classify once per distinct payload prefix rather than per row
    cache: Dict[str, str] = {}

    def classify(p: str) -> str:
        key = p[:64]
        if key not in cache:
            cache[key] = classify_tag_ecosystem_from_payload(p)
        return cache[key]

    return payload.map(classify).str.upper()


def load_capture(path: str) -> pd.DataFrame:
    """Read a capture, attach an ECOSYSTEM column and drop Google connected-state."""
    df = pd.read_csv(path, low_memory=False)
    if "AdvA" not in df.columns:
        raise SystemExit(f"{path}: no AdvA column")
    df = df[df["AdvA"].notna()].copy()
    df["ECOSYSTEM"] = _ecosystem_column(df)
    if "payload" in df.columns:
        # Google connected-state advertisements are not a stable device identity
        drop = df["payload"].astype(str).str.lower().str.contains("aafe40", na=False)
        df = df[~drop].copy()
    return df


def device_specs(df: pd.DataFrame, cfo_col: str) -> List[Tuple[str, str, str]]:
    """Ordered [(mac, 'Apple 1', 'APPLE'), ...] per ecosystem.

    Devices are numbered in ascending MAC order, which is what the paper's panels
    use: against the published Figure 2a medians, MAC order matches 13/15 Apple,
    4/4 Samsung and 3/4 Tile devices, where packet-count order matches 4/15, 0/4
    and 0/4. Where an ecosystem has more devices than the panel shows, the most-seen
    ones are kept and then re-sorted by MAC.
    """
    usable = df[pd.to_numeric(df[cfo_col], errors="coerce").notna()]
    counts = usable.groupby("AdvA").size().to_dict()
    eco_of = usable.groupby("AdvA")["ECOSYSTEM"].first().to_dict()

    specs: List[Tuple[str, str, str]] = []
    for eco in ECOSYSTEMS:
        macs = [m for m, e in eco_of.items() if e == eco and counts.get(m, 0) >= MIN_SAMPLES]
        macs.sort(key=lambda m: counts.get(m, 0), reverse=True)       # keep the most-seen
        macs = macs[: MAX_PER_TYPE.get(eco, 15)]
        for i, mac in enumerate(sorted(macs, key=lambda m: str(m).lower()), 1):
            specs.append((mac, f"{eco.capitalize()} {i}", eco))
    return specs


# --------------------------------------------------------------------------- #
# Drawing
# --------------------------------------------------------------------------- #
def _trim(vals: np.ndarray) -> np.ndarray:
    """Drop per-device outliers outside [p1, p99]; keep everything if that empties."""
    if len(vals) < 10:
        return vals
    lo, hi = np.percentile(vals, [TRIM_LO, TRIM_HI])
    kept = vals[(vals >= lo) & (vals <= hi)]
    return kept if len(kept) >= MIN_SAMPLES else vals


def _violin(ax, pos: float, vals: np.ndarray, face: str, edge: str,
            width: float = VIOLIN_WIDTH) -> None:
    """One tail-free violin: KDE clipped strictly to the observed range."""
    vals = _trim(np.asarray(vals, dtype=float))
    vmin, vmax = float(np.min(vals)), float(np.max(vals))
    if vmax <= vmin:                       # degenerate -> draw a flat marker
        ax.plot([pos - width / 2, pos + width / 2], [vmin, vmin],
                color=edge, linewidth=1.5)
        return
    margin = (vmax - vmin) * 0.01
    grid = np.linspace(vmin - margin, vmax + margin, 100)
    try:
        density = gaussian_kde(vals, bw_method=0.10)(grid)
    except np.linalg.LinAlgError:
        return
    keep = (grid >= vmin) & (grid <= vmax)
    grid, density = grid[keep], density[keep]
    if len(grid) == 0 or density.max() <= 0:
        return
    density = density / density.max() * width / 2
    ax.fill_betweenx(grid, pos - density, pos + density,
                     facecolor=face, edgecolor=edge, alpha=0.80, linewidth=1.0)
    median = float(np.median(vals))
    ax.plot([pos - width / 2, pos + width / 2], [median, median],
            color="#000000", linewidth=0.8, alpha=0.6, zorder=10)


def _style_axes(ax, labels: Sequence[str], ylabel: str,
                xlabel: Optional[str] = "Device") -> None:
    ax.set_ylabel(ylabel, fontsize=10, fontweight="bold")
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=10, fontweight="bold")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_xlim(-0.5, len(labels) - 0.5)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _legend(ax, ecos: Sequence[str]) -> None:
    handles = []
    for eco in ECOSYSTEMS:
        if eco in ecos:
            face, edge = get_device_color(eco)
            handles.append(Patch(facecolor=face, edgecolor=edge,
                                 label=eco.capitalize(), linewidth=1.2))
    if handles:
        # roomier swatches, matching the published panels
        ax.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, 1.01),
                  ncol=len(handles), columnspacing=1.4, handlelength=1.9,
                  handleheight=1.1, borderpad=0.5, frameon=True, fontsize=9)


def plot_per_device_cfo(df: pd.DataFrame, out_pdf: str, cfo_col: str = "CFO_Hz") -> bool:
    """Figures 2a / 3a: one violin of CFO per device, grouped by ecosystem."""
    specs = device_specs(df, cfo_col)
    data, labels, colors, ecos = [], [], [], []
    for mac, label, eco in specs:
        vals = pd.to_numeric(df.loc[df["AdvA"] == mac, cfo_col], errors="coerce").dropna() / 1000.0
        if len(vals) >= MIN_SAMPLES:
            data.append(vals.values)
            labels.append(label)
            colors.append(get_device_color(eco))
            ecos.append(eco)
    if not data:
        print(f"  [!] no devices for {os.path.basename(out_pdf)}")
        return False

    fig, ax = plt.subplots(figsize=(USENIX_2COL_WIDTH, 3.0))
    for pos, (vals, (face, edge)) in enumerate(zip(data, colors)):
        _violin(ax, pos, vals, face, edge)
    _style_axes(ax, labels, "CFO (kHz)")
    _legend(ax, ecos)
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"  wrote {out_pdf}  ({len(labels)} devices)")
    return True


def plot_transition_cfo(df: pd.DataFrame, out_pdf: str) -> bool:
    """Figure 5: four stacked panels, one per symbol transition."""
    panels = [("CFO_00_Hz", r"$\tilde{\delta}_{00}$ (kHz)"),
              ("CFO_01_Hz", r"$\tilde{\delta}_{01}$ (kHz)"),
              ("CFO_10_Hz", r"$\tilde{\delta}_{10}$ (kHz)"),
              ("CFO_11_Hz", r"$\tilde{\delta}_{11}$ (kHz)")]
    panels = [(c, lab) for c, lab in panels if c in df.columns]
    if not panels:
        print("  [!] no transition CFO columns")
        return False

    specs = device_specs(df, "CFO_Hz")
    if not specs:
        return False

    fig, axes = plt.subplots(len(panels), 1, sharex=True,
                             figsize=(USENIX_2COL_WIDTH, 3.85))
    axes = np.atleast_1d(axes)
    labels, ecos = [], []
    for ax_i, (ax, (col, ylab)) in enumerate(zip(axes, panels)):
        labels, ecos = [], []
        for pos, (mac, label, eco) in enumerate(specs):
            vals = pd.to_numeric(df.loc[df["AdvA"] == mac, col], errors="coerce").dropna() / 1000.0
            labels.append(label)
            ecos.append(eco)
            if len(vals) >= MIN_SAMPLES:
                face, edge = get_device_color(eco)
                _violin(ax, pos, vals.values, face, edge)
        ax.set_ylabel(ylab, fontsize=9, fontweight="bold")
        ax.set_xlim(-0.5, len(specs) - 0.5)
        ax.grid(True, axis="y", linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        if ax_i == 0:
            _legend(ax, ecos)
    axes[-1].set_xticks(range(len(labels)))
    axes[-1].set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"  wrote {out_pdf}  ({len(panels)} panels x {len(specs)} devices)")
    return True


def plot_adversary_cfo(path: str, out_pdf: str, cfo_col: str = "CFO_Hz") -> bool:
    """Figure 3b: CFO of the four ESP32 adversaries, identified by payload marker.

    Each adversary packet carries a fresh pseudonym (one MAC per transmission), so
    a single packet gives a noisy CFO. The paper's panel shows the *accumulated*
    estimate -- the mean over ACCUM_PKTS consecutive packets -- which is what makes
    the medians separable "under per-transmission pseudonym rotation".
    """
    df = pd.read_csv(path, low_memory=False, usecols=lambda c: c in ("payload", cfo_col))
    if "payload" not in df.columns:
        print(f"  [!] {path}: no payload column")
        return False
    payload = df["payload"].astype(str).str.lower()

    data, labels = [], []
    for i, tag in enumerate(ADV_TAGS, 1):
        vals = pd.to_numeric(df.loc[payload.str.contains(tag, na=False), cfo_col],
                             errors="coerce").dropna() / 1000.0
        if len(vals) >= MIN_SAMPLES:
            acc = vals.groupby(np.arange(len(vals)) // ACCUM_PKTS).mean()
            # trim as elsewhere, so the extrema whiskers stay close to the body
            data.append(_trim(acc.to_numpy(dtype=float)))
            labels.append(f"Adversary {i}")
    if not data:
        print(f"  [!] no adversary packets in {os.path.basename(path)}")
        return False

    # matplotlib's own violinplot: Scott-rule bandwidth gives the paper's rounded
    # blobs, and showmedians/showextrema draw the median bar + vertical range line
    # that read as the "+" marker in the published panel.
    fig, ax = plt.subplots(figsize=(3.5, 4.0))
    parts = ax.violinplot(data, positions=range(len(data)), widths=0.8,
                          showmedians=True, showextrema=True)
    for body in parts["bodies"]:
        body.set_facecolor("#ef4444")
        body.set_edgecolor("#991b1b")
        body.set_alpha(0.85)
        body.set_linewidth(1.0)
    for key in ("cmedians", "cbars", "cmins", "cmaxes"):
        if key in parts:
            parts[key].set_color("#111111")
            parts[key].set_linewidth(1.0)
    _style_axes(ax, labels, "CFO (kHz)")
    fig.tight_layout()
    fig.savefig(out_pdf)
    plt.close(fig)
    print(f"  wrote {out_pdf}  ({len(labels)} adversaries)")
    return True


def plot_cfo_over_time(csv_path: str, out_pdf: str, workdir: str,
                       bin_minutes: int = 15) -> bool:
    """Figure 2b — delegated to scenario_gen's own drift plotter.

    Unlike the per-device violin helper, `save_cfo_drift_plot_for_all_devices()`
    *does* exist in the shipped scenario_gen.py, and with max_devices_per_type=1
    it reproduces the published panel (one representative tag per ecosystem across
    four 15-minute windows, in matplotlib's default violin styling).
    """
    from scenario_gen import (save_cfo_drift_plot_for_all_devices,
                              compute_persistent_macs_non_samsung,
                              compute_persistent_samsung_privids)
    os.makedirs(workdir, exist_ok=True)
    df = pd.read_csv(csv_path, low_memory=False)

    # Keep only the representative identity per ecosystem, so the plotter's
    # sorted()[:1] selection lands on the device the paper actually shows.
    eco = df["tag_type"].astype(str).str.upper()
    payload = df["payload"].astype(str).str.lower()
    keep = pd.Series(False, index=df.index)
    for name in ECOSYSTEMS:
        idx = FIG2B_REP_INDEX.get(name, 0)
        if name == "SAMSUNG":
            ids = sorted(compute_persistent_samsung_privids(df, "timestamp", "payload",
                                                            "tag_type", 0))
            if len(ids) > idx:
                keep |= (eco == name) & payload.str.contains(str(ids[idx]).lower(), na=False)
        else:
            ids = sorted(compute_persistent_macs_non_samsung(df, "timestamp", "AdvA",
                                                            "tag_type", name, 0))
            if len(ids) > idx:
                # the helper returns lower-cased MACs; the capture stores them upper-cased
                mac = df["AdvA"].astype(str).str.lower()
                keep |= (eco == name) & (mac == str(ids[idx]).lower())
    if keep.any():
        df = df[keep].copy()

    produced, _pkl = save_cfo_drift_plot_for_all_devices(
        df_full=df, ts_col="timestamp", mac_col="AdvA", payload_col="payload",
        tag_col="tag_type", persist_sec=0, outdir=workdir,
        cfo_col="CFO_Hz", bin_minutes=bin_minutes, max_devices_per_type=1,
    )
    if not produced or not os.path.exists(produced):
        print("  [!] scenario_gen drift plotter produced nothing")
        return False
    shutil.copyfile(produced, out_pdf)
    print(f"  wrote {out_pdf}  (via scenario_gen.save_cfo_drift_plot_for_all_devices)")
    return True


# --------------------------------------------------------------------------- #
def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "cfo_figures_out")
    os.makedirs(outdir, exist_ok=True)
    sys.path.insert(0, HERE)          # for scenario_gen.classify_tag_ecosystem_from_payload

    if os.path.exists(SDR_CSV):
        print(f"[SDR] {SDR_CSV}")
        sdr = load_capture(SDR_CSV)
        plot_per_device_cfo(sdr, os.path.join(outdir, "Figure_2a_SDR_B210_PerDevice_CFO.pdf"))
        plot_cfo_over_time(SDR_CSV, os.path.join(outdir, "Figure_2b_SDR_B210_CFO_Over_Time.pdf"),
                           os.path.join(outdir, "_drift"))
        plot_transition_cfo(sdr, os.path.join(outdir, "Figure_5_PerDevice_Transition_CFO.pdf"))
    else:
        print(f"[!] missing {SDR_CSV}")

    if os.path.exists(BLEPHASYR_CSV):
        print(f"[BlePhasyr] {BLEPHASYR_CSV}")
        rail = load_capture(BLEPHASYR_CSV)
        plot_per_device_cfo(rail, os.path.join(outdir, "Figure_3a_BlePhasyr_PerDevice_CFO.pdf"))
    else:
        print(f"[!] missing {BLEPHASYR_CSV}")

    if os.path.exists(ADVERSARY_CSV):
        print(f"[adversaries] {ADVERSARY_CSV}")
        plot_adversary_cfo(ADVERSARY_CSV,
                           os.path.join(outdir, "Figure_3b_BlePhasyr_Adversary_CFO.pdf"))
    else:
        print(f"[!] missing {ADVERSARY_CSV}")

    print(f"\nAll figures written to: {outdir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
