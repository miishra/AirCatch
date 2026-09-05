#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reproduce_paper.py — one command to reproduce the paper's plots and tables.

Paper: "AirCatch: Effectively tracing advanced tag-based trackers"

Runs the shipped pipeline end to end on the four base captures in dataset/ and
curates the results into a single folder, named exactly as the paper labels them:

    Paper_Results/
      Table_1.csv / Table_1.txt          dataset summary
      Table_2.csv / Table_2.txt          detection outcomes
      Figure_2a/2b_*.pdf                 SDR: per-device CFO, CFO over time
      Figure_3a/3b_*.pdf                 BlePhasyr: per-device CFO, adversary CFO
      Figure_5_*.pdf                     per-device transition CFOs
      Figure_6.pdf                       core-density CDF (adv present vs absent)
      Figure_7a..f_*.pdf                 core density over time (6 panels)
      Section_7.2_Fingerprint_Transition_Ablation.csv/.txt
                                         transition-CFO feature ablation
      Section_7.2_Fingerprint_Runs/      per-run reports + confusion matrices
      REPRODUCED.md                      manifest + what is NOT reproducible
      EXTRA/                             every other plot the pipeline emits
        per_scenario/  multiscenario/  walkthrough/  block_benchmark/

Only the paper's figures/tables live at the top of Paper_Results/. All the
auxiliary plots the pipeline produces (PR bars, TTD CDFs, silhouette histograms,
grouped detection bars, per-scenario CDFs, block-size sweep, ...) are moved into
Paper_Results/EXTRA/. No new graphs are created — the paper figures are selected
and renamed from the pipeline's own output.

Every output at the top of Paper_Results/ is generated from dataset/.
  - Figures 2, 3, 5 come from plot_cfo_figures.py (the per-device violin helper
    `save_violin_cfo_for_all_devices` is referenced-but-undefined in the shipped
    scenario_gen.py, so that plotting is reimplemented there).
  - Figures 6, 7 and Tables 1-2 come from Aircatch.py / scenario_gen.py.
  - Section 7.2 comes from fingerprint_classifier.py.

Not covered here: Figures 9, 10 (Ubertooth captures not shipped) and
Figures 1, 8 (hardware photo / protocol diagrams -- not data-generated).

Usage:
  python3 reproduce_paper.py                 # everything (tens of minutes)
  python3 reproduce_paper.py --quick         # smaller block grid, faster
  python3 reproduce_paper.py --stages table1,scenarios,detection
  python3 reproduce_paper.py --force         # rebuild controlled/ scenarios
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent
PY = sys.executable or "python3"
RESULTS = ROOT / "Paper_Results"
EXTRA = RESULTS / "EXTRA"

# source capture -> Aircatch controlled/ subfolder (must match CONTROLLED_SUBFOLDERS)
SOURCES = {
    "HtoW": "dataset/Home_to_work.csv",
    "WtoH": "dataset/Work_to_home.csv",
    "Car_Trip": "dataset/car_trip_final.csv",
    "Airport": "dataset/airport_total_trip.csv",
}
PRETTY = {"HtoW": "Home->Work", "WtoH": "Work->Home",
          "Car_Trip": "Car commute", "Airport": "Airport (no adv.)"}
# source-file stem (as it appears in generated paths) -> subfolder key
STEM_TO_SUB = {
    "Home_to_work": "HtoW", "Work_to_home": "WtoH",
    "car_trip_final": "Car_Trip", "airport_total_trip": "Airport",
}
ADV_TAGS = ["4c001219ff", "4c001219fc", "4c001219fd", "4c001219fe"]
BENIGN_ONLY = {"Airport"}  # paper's adversary-absent stress test
SEED = 1337

# Figure 7: core density over time, plotted with the delta=1.15 line.
# Its scenarios are generated from dataset/ by scenario_gen.py, separately from the
# `scenarios` stage because two settings differ:
#   * --persist-minutes 75 keeps the full background. scenario_gen drops devices it
#     considers persistent (they could be trackers); at the 25-minute default that
#     strips ~76% of the background, at 75 nothing qualifies and all of it stays.
#   * one adversary per route, and a different tag for each (fd / fc / ff), which is
#     what sets each panel's core-density scale.
# With these settings the generated CSVs match the runs the published panels used
# (Home->Work: 12,262 rows, 198 identities, exact overlap on (timestamp, CFO_Hz)).
#   (letter, label, capture stem, adversary tag or None for the background panel)
FIG7_PERSIST_MIN = 75
FIG7_PANELS = [
    ("a", "HomeToWork_background", "Home_to_work", None),
    ("b", "WorkToHome_background", "Work_to_home", None),
    ("c", "CarCommute_background", "car_trip_final", None),
    ("d", "HomeToWork_adversary", "Home_to_work", "4c001219fd"),
    ("e", "WorkToHome_adversary", "Work_to_home", "4c001219fc"),
    ("f", "CarCommute_adversary", "car_trip_final", "4c001219ff"),
]
FIG7_WORK = ROOT / ".fig7_work"   # generated scenarios + per-panel copies

# Section 7.2 fingerprint ablation: one classifier, two captures, two feature sets.
# fingerprint_classifier.py is interactive; the two prompts are the statistic choice
# ("1" = mean) and the CFO-column choice (blank = carrier CFO only, else the menu
# indices). The BlePhasyr capture also carries CFO_from_transitions_Hz, so its menu
# has one more entry than the SDR one.
FP_SCRIPT = ROOT / "fingerprint_classifier.py"
FP_WORK = ROOT / ".fingerprint_work"
FP_CONFIGS = [
    ("blephasyr_carrier_cfo_only", "dataset/blephasyr_static_devices.csv", ""),
    ("blephasyr_all_cfo_features", "dataset/blephasyr_static_devices.csv", "1,2,3,4,5,6"),
    ("sdr_b210_carrier_cfo_only", "dataset/sdr_b210_static_devices.csv", ""),
    ("sdr_b210_all_cfo_features", "dataset/sdr_b210_static_devices.csv", "1,2,3,4,5"),
]
# (capture label, all-features run, carrier-only run)
FP_PAIRS = [
    ("BlePhasyr (EFR32MG24)", "blephasyr_all_cfo_features", "blephasyr_carrier_cfo_only"),
    ("USRP B210 (SDR)", "sdr_b210_all_cfo_features", "sdr_b210_carrier_cfo_only"),
]
FP_OUT_STEM = "Section_7.2_Fingerprint_Transition_Ablation"
FP_RUNS_DIR = "Section_7.2_Fingerprint_Runs"

# Figures 2, 3, 5: CFO fingerprints over the shipped captures. Regenerated by
# plot_cfo_figures.py -- the helper that originally drew them
# (`save_violin_cfo_for_all_devices`) is referenced but never defined in the
# shipped scenario_gen.py, so the plotting is reimplemented there.
#   Figure 2  (a) USRP B210 per-device CFO   (b) CFO over four 15-min windows
#   Figure 3  (a) BlePhasyr per-device CFO   (b) the four ESP32 adversaries
#   Figure 5  per-device transition CFOs (00/01/10/11)
F235_SCRIPT = ROOT / "plot_cfo_figures.py"
F235_WORK = ROOT / ".cfo_figures_work"
F235_OUTPUTS = [
    "Figure_2a_SDR_B210_PerDevice_CFO.pdf",
    "Figure_2b_SDR_B210_CFO_Over_Time.pdf",
    "Figure_3a_BlePhasyr_PerDevice_CFO.pdf",
    "Figure_3b_BlePhasyr_Adversary_CFO.pdf",
    "Figure_5_PerDevice_Transition_CFO.pdf",
]


ENV = dict(os.environ)
ENV.setdefault("MPLBACKEND", "Agg")
ENV.setdefault("MPLCONFIGDIR", str(ROOT / ".mplconfig"))
ENV.setdefault("PYTHONUNBUFFERED", "1")


def log(msg: str) -> None:
    print(f"\n\033[1m==> {msg}\033[0m", flush=True)


def run(cmd, stdin_text=None, check=True):
    print(f"    $ {' '.join(str(c) for c in cmd)}", flush=True)
    r = subprocess.run([str(c) for c in cmd], cwd=str(ROOT), env=ENV,
                       input=stdin_text, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"Command failed ({r.returncode}): {' '.join(map(str, cmd))}")
    return r.returncode


# --------------------------------------------------------------------------- #
# Stage 1: Table 1
# --------------------------------------------------------------------------- #
def stage_table1() -> None:
    log("Table 1 — dataset summary")
    import pandas as pd

    RESULTS.mkdir(parents=True, exist_ok=True)
    rows, tot = [], [0.0, 0, 0]
    for key in ["HtoW", "WtoH", "Car_Trip", "Airport"]:
        f = ROOT / SOURCES[key]
        if not f.exists():
            print(f"    [WARN] missing {f}; skipping")
            continue
        d = pd.read_csv(f, usecols=["timestamp", "AdvA"])
        ts = pd.to_numeric(d["timestamp"], errors="coerce").dropna()
        dur = (ts.max() - ts.min()) / 60.0 if len(ts) else float("nan")
        npk, nmac = len(d), int(d["AdvA"].astype(str).nunique())
        rows.append((PRETTY[key], round(dur, 1), npk, nmac))
        tot[0] += dur; tot[1] += npk; tot[2] += nmac
    rows.append(("Total", round(tot[0], 1), tot[1], tot[2]))

    with open(RESULTS / "Table_1.csv", "w") as fh:
        fh.write("Scenario,Duration_min,Packets,MACs\n")
        for name, dur, npk, nmac in rows:
            fh.write(f"{name},{dur},{npk},{nmac}\n")
    hdr = f"{'Scenario':<20}{'Dur (min)':>12}{'#Packets':>12}{'#MACs':>10}"
    lines = ["Table 1: Dataset summary", "", hdr, "-" * len(hdr)]
    lines += [f"{n:<20}{d:>12}{p:>12,}{m:>10,}" for n, d, p, m in rows]
    (RESULTS / "Table_1.txt").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))


# --------------------------------------------------------------------------- #
# Stage 2: scenario generation
# --------------------------------------------------------------------------- #
def _controlled_has_content(sub: str) -> bool:
    return any((ROOT / "controlled" / sub).glob("scenarios_*"))


def stage_scenarios(force: bool) -> None:
    log("Scenario generation — building controlled/ from dataset/")
    for sub, src in SOURCES.items():
        dst = ROOT / "controlled" / sub
        if force and dst.exists():
            print(f"    [force] removing {dst.relative_to(ROOT)}")
            shutil.rmtree(dst)
        if _controlled_has_content(sub):
            print(f"    [skip] {dst.relative_to(ROOT)} already populated (use --force)")
            continue
        dst.mkdir(parents=True, exist_ok=True)

        print(f"    [{sub}] adv0 baseline")
        run([PY, "scenario_gen.py", "--input", src, "--outdir", f"controlled/{sub}",
             "--seed", str(SEED)], stdin_text="\n" * 12)
        if sub in BENIGN_ONLY:
            continue
        for n in range(1, len(ADV_TAGS) + 1):
            tags = ",".join(ADV_TAGS[:n])
            print(f"    [{sub}] adv{n} ({tags})")
            run([PY, "scenario_gen.py", "--input", src, "--outdir", f"controlled/{sub}",
                 "--seed", str(SEED), "--select-adv-tags", tags])


# --------------------------------------------------------------------------- #
# Stage 3: detection
# --------------------------------------------------------------------------- #
def stage_detection() -> None:
    log("Detection — per-scenario eval + multiscenario aggregate")
    for sub in SOURCES:
        if not _controlled_has_content(sub):
            print(f"    [WARN] controlled/{sub} empty; run the scenarios stage first")
            continue
        print(f"    [{sub}] per-scenario eval")
        run([PY, "Aircatch.py", "--input", f"controlled/{sub}"])
    print("    [all] multiscenario aggregate")
    run([PY, "Aircatch.py", "--run-multiscenario"])


# --------------------------------------------------------------------------- #
# Stage 3b: Figure 7 (deterministic, from the raw captures)
# --------------------------------------------------------------------------- #
def stage_figure7(force: bool = False) -> None:
    log("Figure 7 — core density over time (delta=1.15 line)")
    FIG7_WORK.mkdir(parents=True, exist_ok=True)
    for letter, label, stem, tag in FIG7_PANELS:
        src_capture = ROOT / "dataset" / f"{stem}.csv"
        if not src_capture.exists():
            print(f"    [WARN] missing dataset/{stem}.csv; skipping 7{letter}")
            continue
        dst = FIG7_WORK / f"fig7{letter}_{label}.csv"
        if not dst.exists() or force:
            gen = FIG7_WORK / "gen" / f"fig7{letter}"
            if gen.exists():
                shutil.rmtree(gen)
            gen.mkdir(parents=True, exist_ok=True)
            cmd = [PY, "scenario_gen.py", "--input", f"dataset/{stem}.csv",
                   "--outdir", str(gen.relative_to(ROOT)), "--seed", str(SEED),
                   "--persist-minutes", str(FIG7_PERSIST_MIN)]
            if tag:
                run(cmd + ["--select-adv-tags", tag])
                wanted = "scenario_tx-1min_rot-1min.csv"      # the stealth adversary
            else:
                run(cmd, stdin_text="\n" * 12)                # no re-introduction
                wanted = "background_only.csv"
            hits = sorted(gen.glob(f"scenarios_*/{wanted}"))
            if not hits:
                print(f"    [WARN] scenario_gen produced no {wanted} for 7{letter}")
                continue
            shutil.copy2(hits[0], dst)
        print(f"    [7{letter}] {label}" + (f"  (adv tag {tag})" if tag else "  (background)"))
        run([PY, "Aircatch.py", "--input", str(dst.relative_to(ROOT))])


# --------------------------------------------------------------------------- #
# Stage 3d: Figures 2, 3, 5 — CFO fingerprints
# --------------------------------------------------------------------------- #
def stage_figures(force: bool = False) -> None:
    """Figures 2, 3, 5 — regenerated from the shipped captures."""
    log("Figures 2, 3, 5 — CFO fingerprints from dataset/")
    if not F235_SCRIPT.exists():
        print(f"    [WARN] {F235_SCRIPT.name} not found; skipping")
        return
    if all((F235_WORK / n).exists() for n in F235_OUTPUTS) and not force:
        print("    [skip] already generated (use --force to re-run)")
        return
    run([PY, F235_SCRIPT.name, str(F235_WORK)])


# --------------------------------------------------------------------------- #
# Stage 3c: Section 7.2 fingerprint transition-feature ablation
# --------------------------------------------------------------------------- #
def stage_fingerprint(force: bool = False) -> None:
    log("Fingerprint ablation (§7.2) — carrier CFO only vs. all CFO features")
    if not FP_SCRIPT.exists():
        print(f"    [WARN] {FP_SCRIPT.name} not found; skipping the fingerprint stage")
        return
    for name, csv, sel in FP_CONFIGS:
        if not (ROOT / csv).exists():
            print(f"    [WARN] missing {csv}; skipping {name}")
            continue
        out = FP_WORK / name
        if (out / "classification_report.txt").exists() and not force:
            print(f"    [skip] {name} (use --force to re-run)")
            continue
        print(f"    [{name}]")
        # stdin: statistic choice, then CFO-column choice
        run([PY, FP_SCRIPT.name, csv, str(out)], stdin_text=f"1\n{sel}\n")
        # normalise the classifier's output filenames
        for src, dst in (("ble_fingerprint_classification_results.txt", "classification_report.txt"),
                         ("ble_fingerprint_confusion_matrix.png", "confusion_matrix.png"),
                         ("ble_fingerprint_feature_distribution.png", "feature_distribution.png")):
            if (out / src).exists():
                (out / src).rename(out / dst)


# --------------------------------------------------------------------------- #
# Section 7.2 comparison table (built from the four classification reports)
# --------------------------------------------------------------------------- #
_FP_CLASS_RE = re.compile(r"\s*(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s*$")
_FP_HDR_RE = {
    "csv": re.compile(r"Input CSV:\s*(.+)"),
    "acc": re.compile(r"Accuracy:\s*([\d.]+)%"),
    "prec": re.compile(r"Precision:\s*([\d.]+)%"),
    "rec": re.compile(r"Recall:\s*([\d.]+)%"),
    "f1": re.compile(r"F1-Score:\s*([\d.]+)%"),
    "ncls": re.compile(r"Number of MAC classes:\s*(\d+)"),
}


def _fp_parse(path: Path) -> dict:
    txt = path.read_text(errors="ignore")
    out = {k: (m.group(1).strip() if (m := rx.search(txt)) else None)
           for k, rx in _FP_HDR_RE.items()}
    per_class, in_rep = {}, False
    for line in txt.splitlines():
        if "Per-MAC Classification Report" in line:
            in_rep = True
            continue
        if not in_rep or line.strip().startswith(("accuracy", "macro avg", "weighted avg")):
            continue
        if (m := _FP_CLASS_RE.match(line)):
            per_class[m.group(1)] = (float(m.group(2)), float(m.group(3)),
                                     float(m.group(4)), int(m.group(5)))
    out["per_class"] = per_class
    return out


def _fp_wf1(keys, per_class) -> float:
    sup = sum(per_class[k][3] for k in keys)
    return sum(per_class[k][2] * per_class[k][3] for k in keys) / sup if sup else float("nan")


def build_fingerprint_summary() -> bool:
    """Write the §7.2 ablation comparison into Paper_Results/."""
    log("Section 7.2 — fingerprint transition-feature comparison")
    RESULTS.mkdir(parents=True, exist_ok=True)
    rows = [("capture", "feature_set", "input_csv", "n_classes", "accuracy_pct",
             "precision_pct", "recall_pct", "f1_pct",
             "f1_rotating_id_trackers", "f1_fixed_mac_devices")]
    lines = [
        "Section 7.2 -- transition-CFO features: effect on per-device fingerprinting",
        "=" * 78, "",
        "Each capture is classified twice with the SAME device classes and the SAME",
        "train/test windows; the only difference is whether the per-symbol transition",
        "CFOs (00/11/10/01, plus CFO_from_transitions where present) are given to the",
        "Random Forest alongside the single carrier CFO.",
        "",
        "'Rotating-ID trackers' are the privacy-ID devices (Samsung SmartTag PRIVID,",
        "UUID 0xFD5A) that re-randomise their identifier -- the rogue-tracker case",
        "AirCatch must link across pseudonym changes.",
        "",
    ]
    found = 0
    for label, all_run, only_run in FP_PAIRS:
        pa = FP_WORK / all_run / "classification_report.txt"
        pb = FP_WORK / only_run / "classification_report.txt"
        if not (pa.exists() and pb.exists()):
            print(f"    [WARN] missing reports for {label}")
            continue
        found += 1
        A, B = _fp_parse(pa), _fp_parse(pb)
        keys = sorted(set(A["per_class"]) & set(B["per_class"]))
        trk = [k for k in keys if ":" not in k]      # PRIVID => rotating identity
        fix = [k for k in keys if ":" in k]
        for tag, R in (("all CFO features", A), ("carrier CFO only", B)):
            rows.append((label, tag, Path(R["csv"] or "").name, R["ncls"] or "",
                         R["acc"] or "", R["prec"] or "", R["rec"] or "", R["f1"] or "",
                         f"{_fp_wf1(trk, R['per_class']):.4f}" if trk else "",
                         f"{_fp_wf1(fix, R['per_class']):.4f}" if fix else ""))
        ta, tb = _fp_wf1(trk, A["per_class"]), _fp_wf1(trk, B["per_class"])
        fa, fb = _fp_wf1(fix, A["per_class"]), _fp_wf1(fix, B["per_class"])
        lines += [
            f"--- {label} ---",
            f"    input CSV : {Path(A['csv'] or '').name}",
            f"    classes   : {A['ncls']}  ({len(trk)} rotating-ID trackers, {len(fix)} fixed-MAC)",
            "",
            f"    {'':<26}{'carrier CFO only':>18}{'+ all CFO feats':>20}{'delta':>10}",
            f"    {'accuracy':<26}{float(B['acc']):>17.2f}%{float(A['acc']):>19.2f}%"
            f"{float(A['acc'])-float(B['acc']):>+10.2f}",
            f"    {'F1 (weighted)':<26}{float(B['f1']):>17.2f}%{float(A['f1']):>19.2f}%"
            f"{float(A['f1'])-float(B['f1']):>+10.2f}",
            f"    {'F1 rotating-ID trackers':<26}{tb:>18.3f}{ta:>20.3f}{ta-tb:>+10.3f}",
            f"    {'F1 fixed-MAC devices':<26}{fb:>18.3f}{fa:>20.3f}{fa-fb:>+10.3f}",
            "",
            "    per-tracker F1 (carrier CFO only -> all CFO features):",
        ]
        lines += [f"      {k:<20} {B['per_class'][k][2]:.2f}  ->  {A['per_class'][k][2]:.2f}"
                  for k in trk]
        lines.append("")

    if found == 0:
        print("    [WARN] no fingerprint runs found; run the fingerprint stage")
        return False
    (RESULTS / f"{FP_OUT_STEM}.csv").write_text(
        "\n".join(",".join(f'"{c}"' for c in r) for r in rows) + "\n")
    (RESULTS / f"{FP_OUT_STEM}.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return True


# --------------------------------------------------------------------------- #
# Stage 4: block-size calibration
# --------------------------------------------------------------------------- #
def stage_blocks(quick: bool, blocks: str, workers: int) -> None:
    log("Block-size calibration (Experiment 2 / Main Result 3)")
    cmd = [PY, "block_benchmark.py", "--scenarios", "HtoW,WtoH,Airport,Car_Trip",
           "--outdir", "block_benchmark_out"]
    if blocks:
        cmd += ["--blocks", blocks]
    elif quick:
        cmd += ["--blocks", "1200,2400,3600"]
    if workers:
        cmd += ["--workers", str(workers)]
    run(cmd)


# --------------------------------------------------------------------------- #
# Table 2 — build a detection matrix from the per-scenario eval reports
# --------------------------------------------------------------------------- #
_LINE_RE = re.compile(r"(?P<path>\S+\.csv):\s+gt_pos=(?P<gt>True|False)\s+pred_pos=(?P<pred>True|False)")


def build_table2() -> bool:
    log("Table 2 — detection outcomes")
    reports = sorted(glob.glob(str(ROOT / "aircatch_folder_*_eval_report__*.txt")))
    if not reports:
        print("    [WARN] no per-scenario eval reports found; run the detection stage")
        return False

    # cell[sub][adv] = [n_csvs, n_detected, n_false_pos]
    cell = {}
    for rep in reports:
        for line in Path(rep).read_text(errors="ignore").splitlines():
            m = _LINE_RE.search(line)
            if not m:
                continue
            path = m.group("path")
            gt = m.group("gt") == "True"
            pred = m.group("pred") == "True"
            sub = next((v for stem, v in STEM_TO_SUB.items() if stem in path), None)
            am = re.search(r"__adv(\d+)_", path)
            if sub is None or am is None:
                continue
            adv = int(am.group(1))
            c = cell.setdefault(sub, {}).setdefault(adv, [0, 0, 0])
            c[0] += 1
            if gt and pred:
                c[1] += 1
            if (not gt) and pred:
                c[2] += 1

    subs = [s for s in ["HtoW", "WtoH", "Car_Trip", "Airport"] if s in cell]
    advs = sorted({a for s in cell for a in cell[s]})

    # CSV: one row per (scenario, adv) with counts + verdict
    with open(RESULTS / "Table_2.csv", "w") as fh:
        fh.write("Scenario,AdvSetting,n_csvs,n_detected,n_false_pos,verdict\n")
        for s in subs:
            for a in advs:
                if a not in cell[s]:
                    continue
                n, det, fp = cell[s][a]
                if a == 0:
                    verdict = "OK" if fp == 0 else "FALSE_POSITIVE"
                else:
                    verdict = "DETECTED" if det > 0 else "MISSED"
                fh.write(f"{PRETTY[s]},adv{a},{n},{det},{fp},{verdict}\n")

    # TXT: compact check-mark matrix (paper Table 2 style)
    def mark(s, a):
        if a not in cell[s]:
            return "  -  "
        n, det, fp = cell[s][a]
        if a == 0:
            return "  ✓  " if fp == 0 else f" FP:{fp} "
        return f"✓{det}/{n}" if det > 0 else f" 0/{n} "

    colw = 8
    head = f"{'Scenario':<18}" + "".join(f"{('adv'+str(a)):>{colw}}" for a in advs)
    lines = ["Table 2: AirCatch tracker detection",
             "(adv0 = benign; ✓ = correct behaviour: no false alarm / adversary detected)",
             "", head, "-" * len(head)]
    for s in subs:
        lines.append(f"{PRETTY[s]:<18}" + "".join(f"{mark(s, a):>{colw}}" for a in advs))
    (RESULTS / "Table_2.txt").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))
    return True


# --------------------------------------------------------------------------- #
# Curate: select paper figures, then sweep everything else into EXTRA/
# --------------------------------------------------------------------------- #
def _copy(src: Path, dst: Path) -> bool:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"    Figure -> {dst.relative_to(ROOT)}")
        return True
    return False


def _move_into(src: Path, extra_sub: str) -> None:
    if not src.exists():
        return
    dst = EXTRA / extra_sub
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    print(f"    EXTRA  <- {extra_sub}/")


def curate() -> None:
    log("Curating Paper_Results/ (paper figures at top, rest into EXTRA/)")
    RESULTS.mkdir(parents=True, exist_ok=True)

    # Figures 2, 3, 5: regenerated from dataset/ by plot_cfo_figures.py
    for name in F235_OUTPUTS:
        if not _copy(F235_WORK / name, RESULTS / name):
            print(f"    [WARN] {name} not found (run the figures stage)")

    # Figure 6: core-density CDF across scenarios (from multiscenario_results/)
    fig6 = ROOT / "multiscenario_results" / "core_density_cdf_adv_present_vs_absent__overlay__adv_mac_pct.pdf"
    if not _copy(fig6, RESULTS / "Figure_6.pdf"):
        print("    [WARN] Figure 6 not found (run the detection stage)")

    # Figure 7 panels: paper scenarios re-plotted with the delta line.
    found7 = 0
    for letter, label, _stem, _tag in FIG7_PANELS:
        stem = f"fig7{letter}_{label}"
        pat = str(ROOT / "walkthrough_plots" / stem / f"walkthrough__{stem}__dens_vs_time.pdf")
        hits = sorted(glob.glob(pat))
        if hits and _copy(Path(hits[0]), RESULTS / f"Figure_7{letter}_{label}.pdf"):
            found7 += 1
        else:
            print(f"    [WARN] Figure 7{letter} ({label}) not found")
    if found7 == 0:
        print("    [WARN] no Figure 7 panels found (run the figure7 stage)")

    # Section 7.2 fingerprint ablation: per-run outputs sit at the top level too
    # (this is a paper result, not an auxiliary plot).
    if FP_WORK.exists():
        dst = RESULTS / FP_RUNS_DIR
        if dst.exists():
            shutil.rmtree(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(FP_WORK, dst)   # copy: FP_WORK is the re-run cache
        print(f"    Figure -> {dst.relative_to(ROOT)}/")
    # older layouts put these under EXTRA/; drop the stale copy
    stale = EXTRA / "fingerprint"
    if stale.exists():
        shutil.rmtree(stale)

    # Everything else -> EXTRA/
    # per-scenario single-run outputs live at repo root as aircatch_folder_*.
    ps = EXTRA / "per_scenario"
    moved_ps = False
    for pat in ("aircatch_folder_*", "aircatch_single_*"):
        for f in glob.glob(str(ROOT / pat)):
            ps.mkdir(parents=True, exist_ok=True)
            shutil.move(f, str(ps / Path(f).name))
            moved_ps = True
    if moved_ps:
        print("    EXTRA  <- per_scenario/")
    _move_into(ROOT / "multiscenario_results", "multiscenario")
    _move_into(ROOT / "walkthrough_plots", "walkthrough")
    _move_into(ROOT / "block_benchmark_out", "block_benchmark")
    if FIG7_WORK.exists():
        shutil.rmtree(FIG7_WORK)  # remove intermediate stripped CSVs


def write_manifest() -> None:
    log("Writing Paper_Results/REPRODUCED.md")
    RESULTS.mkdir(parents=True, exist_ok=True)
    present = lambda name: "yes" if (RESULTS / name).exists() else "MISSING (run stages)"
    fig7 = sorted(p.name for p in RESULTS.glob("Figure_7*.pdf"))
    lines = [
        "# Paper reproduction", "",
        f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by reproduce_paper.py_", "",
        "## Reproduced (top of Paper_Results/)", "",
        f"- **Table 1** dataset summary — `Table_1.csv` / `Table_1.txt` — {present('Table_1.csv')}",
        "- **Figure 2** stability of CFO fingerprints under SDR capture — "
        f"(a) per-device CFO `Figure_2a_SDR_B210_PerDevice_CFO.pdf` "
        f"({present('Figure_2a_SDR_B210_PerDevice_CFO.pdf')}); "
        f"(b) CFO over four 15-min windows `Figure_2b_SDR_B210_CFO_Over_Time.pdf` "
        f"({present('Figure_2b_SDR_B210_CFO_Over_Time.pdf')})",
        "- **Figure 3** BlePhasyr — "
        f"(a) per-device CFO `Figure_3a_BlePhasyr_PerDevice_CFO.pdf` "
        f"({present('Figure_3a_BlePhasyr_PerDevice_CFO.pdf')}); "
        f"(b) four ESP32 adversary trackers `Figure_3b_BlePhasyr_Adversary_CFO.pdf` "
        f"({present('Figure_3b_BlePhasyr_Adversary_CFO.pdf')})",
        "- **Figure 5** per-device transition CFOs (00/01/10/11) — "
        f"`Figure_5_PerDevice_Transition_CFO.pdf` — {present('Figure_5_PerDevice_Transition_CFO.pdf')}",
        f"- **Table 2** detection outcomes — `Table_2.csv` / `Table_2.txt` — {present('Table_2.csv')}",
        f"- **Figure 6** core-density CDF — `Figure_6.pdf` — {present('Figure_6.pdf')}",
        "- **Figure 7** core density over time — paper's saved scenarios re-plotted with "
        "the delta=1.15 line (a-c backgrounds; adversary tags HtoW=fd, WtoH=fc, Car=ff; "
        "single adversary, tx-1min stealth) — panels: "
        + (", ".join(f"`{n}`" for n in fig7) if fig7 else "MISSING (run stages)"),
        f"- **Section 7.2** fingerprint transition-feature ablation — "
        f"`{FP_OUT_STEM}.txt` / `.csv` — {present(FP_OUT_STEM + '.txt')}. "
        "One classifier, two captures, two feature sets (carrier CFO only vs. all "
        "CFO features incl. the 00/11/10/01 transition CFOs). Per-run classification "
        f"reports, confusion matrices and feature distributions: `{FP_RUNS_DIR}/`.",
        "",
        "## EXTRA/ (auxiliary plots the pipeline emits; not paper figures)", "",
        "- `EXTRA/per_scenario/`  eval reports, PR bars, TTD CDFs, silhouette hists, per-scenario CDFs",
        "- `EXTRA/multiscenario/` grouped detection bars, TP% bars, aggregate CSV, other CDFs",
        "- `EXTRA/walkthrough/`   every temporal-walkthrough panel (all scenarios / tx)",
        "- `EXTRA/block_benchmark/` block-size sweep (Main Result 3 calibration; no paper figure)",
        "",
        "## How each output is produced", "",
        "- **Figures 2, 3, 5** — `plot_cfo_figures.py`, from the static-device captures",
        "  (`sdr_b210_static_devices.csv`, `blephasyr_static_devices.csv`) and, for the",
        "  adversary panel, `car_trip_final.csv`. Devices are numbered in ascending MAC",
        "  order; Figure 2b delegates to `scenario_gen.save_cfo_drift_plot_for_all_devices()`.",
        "  The per-device violin helper `save_violin_cfo_for_all_devices()` is *called but",
        "  never defined* in the shipped `scenario_gen.py`, so that plotting is reimplemented.",
        "- **Figures 6, 7 and Tables 1-2** — `Aircatch.py` / `scenario_gen.py`, from the four",
        "  mobility traces. Figure 7 generates its own scenarios (--persist-minutes 75,",
        "  one adversary per route: fd / fc / ff).",
        "- **Section 7.2** — `fingerprint_classifier.py`, run twice per capture.",
        "",
        "## Not covered by this artifact", "",
        "- **Figures 9, 10** — Ubertooth FREQEST captures: not shipped.",
        "- **Figures 1, 8** — hardware photo and protocol-structure diagrams: not data-generated.",
        "",
    ]
    (RESULTS / "REPRODUCED.md").write_text("\n".join(lines))
    print("\n".join(lines[: lines.index("## Not covered by this artifact")]))


# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Reproduce the paper's plots and tables into Paper_Results/.")
    ap.add_argument("--stages", default="table1,scenarios,detection,figure7,figures,fingerprint,blocks",
                    help="Comma-separated subset of: "
                         "table1,scenarios,detection,figure7,figures,fingerprint,blocks")
    ap.add_argument("--force", action="store_true",
                    help="Rebuild controlled/ scenarios and re-run the fingerprint "
                         "ablation instead of reusing existing outputs")
    ap.add_argument("--quick", action="store_true", help="Smaller block grid (1200,2400,3600)")
    ap.add_argument("--blocks", default="", help="Explicit block grid (overrides --quick)")
    ap.add_argument("--workers", type=int, default=0, help="Worker count for block_benchmark")
    args = ap.parse_args()

    if not (ROOT / "dataset" / "Home_to_work.csv").exists():
        raise SystemExit("dataset/ base captures not found; run from the repo root.")

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    t0 = time.time()
    print(f"AirCatch paper reproduction — stages: {stages}")

    if "table1" in stages:
        stage_table1()
    if "scenarios" in stages:
        stage_scenarios(force=args.force)
    if "detection" in stages:
        stage_detection()
    if "figure7" in stages:
        stage_figure7(force=args.force)
    if "figures" in stages:
        stage_figures(force=args.force)
    if "fingerprint" in stages:
        stage_fingerprint(force=args.force)
    if "blocks" in stages:
        stage_blocks(quick=args.quick, blocks=args.blocks, workers=args.workers)

    # Curation runs whenever detection/figure7/fingerprint outputs may exist.
    if "detection" in stages:
        build_table2()
    if "fingerprint" in stages:
        build_fingerprint_summary()   # reads FP_WORK, so run before curate()
    if {"detection", "figure7", "figures", "fingerprint"} & set(stages):
        curate()
    write_manifest()
    log(f"Done in {time.time() - t0:.0f}s. See Paper_Results/")


if __name__ == "__main__":
    main()
