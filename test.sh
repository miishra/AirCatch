#!/usr/bin/env bash
#
# AirCatch functional test.
#
#   ./test.sh                 # from the repo root, or inside the container
#
# Exercises the full host-side path end to end:
#   1. environment / dependency versions
#   2. detector CLI loads
#   3. detector runs on a shipped base capture
#   4. scenario generation from that base capture
#   5. detector runs on a generated adversary scenario
#
# Exits 0 only if every stage passes. Writes all output to a scratch directory
# so the repository is left untouched.

set -uo pipefail
cd "$(dirname "$0")"

WORK="${AIRCATCH_TEST_DIR:-$(mktemp -d)}"
PASS=0
FAIL=0

ok()   { echo "  [ PASS ] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [ FAIL ] $1"; FAIL=$((FAIL+1)); }
note() { echo "  ....... $1"; }

echo "=============================================="
echo " AirCatch functional test"
echo " workdir: $WORK"
echo "=============================================="

# ---------------------------------------------------------------- 1. environment
echo
echo "[1/5] Environment"
PYV=$(python3 -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])')
if python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)'; then
    ok "Python $PYV (>= 3.10)"
else
    bad "Python $PYV is below the required 3.10"
fi

python3 - <<'PY'
import importlib.metadata as md
import sys
need = ["numpy", "pandas", "scikit-learn", "matplotlib", "scipy"]
missing = []
for p in need:
    try:
        print(f"  ....... {p} {md.version(p)}")
    except Exception:
        missing.append(p)
if missing:
    print("  [ FAIL ] missing packages: " + ", ".join(missing))
    sys.exit(1)
PY
if [ $? -eq 0 ]; then ok "required packages importable"; else bad "dependency import failed"; fi

# ---------------------------------------------------------------- 2. CLI loads
echo
echo "[2/5] Detector CLI"
if python3 Aircatch.py --help >"$WORK/help.txt" 2>&1; then
    ok "Aircatch.py --help"
else
    bad "Aircatch.py --help exited non-zero"; sed 's/^/         /' "$WORK/help.txt" | tail -15
fi
if python3 block_benchmark.py --help >"$WORK/bb_help.txt" 2>&1; then
    ok "block_benchmark.py --help"
else
    bad "block_benchmark.py --help exited non-zero"
fi

# ---------------------------------------------------------------- 3. base capture
echo
echo "[3/5] Detector on a shipped base capture"
BASE="dataset/airport_total_trip.csv"
if [ ! -f "$BASE" ]; then
    bad "$BASE not found"
else
    mkdir -p "$WORK/base" && ( cd "$WORK/base" && \
        python3 "$OLDPWD/Aircatch.py" --input "$OLDPWD/$BASE" ) >"$WORK/base.log" 2>&1
    if [ $? -eq 0 ]; then
        ok "detector completed on $(basename "$BASE")"
        n=$(find "$WORK/base" -name 'aircatch_*' | wc -l)
        note "$n output files"
        for suffix in eval_report__dens1.15.txt meta__dens1.15.csv candidate_checks__dens1.15.csv; do
            if find "$WORK/base" -name "*_$suffix" | grep -q .; then ok "wrote *_$suffix"
            else bad "missing *_$suffix"; fi
        done
    else
        bad "detector failed on $(basename "$BASE")"; tail -15 "$WORK/base.log" | sed 's/^/         /'
    fi
fi

# ---------------------------------------------------------------- 4. scenario gen
echo
echo "[4/5] Scenario generation"
SCEN="$WORK/controlled"
printf '\n%.0s' {1..12} | python3 scenario_gen.py \
    --input dataset/car_trip_final.csv \
    --outdir "$SCEN/Car_Trip" \
    --seed 1337 \
    --select-adv-tags 4c001219fc >"$WORK/gen.log" 2>&1
if [ $? -eq 0 ]; then
    ngen=$(find "$SCEN" -name 'scenario_tx-*_rot-*.csv' | wc -l)
    if [ "$ngen" -eq 5 ]; then ok "generated $ngen (tx, rot) scenario CSVs"
    else bad "expected 5 scenario CSVs, got $ngen"; fi
else
    bad "scenario_gen.py exited non-zero"; tail -15 "$WORK/gen.log" | sed 's/^/         /'
fi

# ---------------------------------------------------------------- 5. adversary run
echo
echo "[5/5] Detector on a generated adversary scenario"
RUNDIR=$(find "$SCEN" -mindepth 1 -maxdepth 1 -type d | head -1)
if [ -z "$RUNDIR" ]; then
    bad "no generated run folder to analyse"
else
    mkdir -p "$WORK/adv" && ( cd "$WORK/adv" && \
        python3 "$OLDPWD/Aircatch.py" --input "$RUNDIR" ) >"$WORK/adv.log" 2>&1
    if [ $? -eq 0 ]; then
        ok "detector completed on $(basename "$RUNDIR")"
        rep=$(find "$WORK/adv" -name '*_eval_report__*.txt' | head -1)
        if [ -n "$rep" ]; then
            note "evaluation report:"
            grep -iE '^(precision|recall|f1|tp|fp|fn|tn)' "$rep" | head -8 | sed 's/^/         /'
        fi
    else
        bad "detector failed on the generated scenario"; tail -15 "$WORK/adv.log" | sed 's/^/         /'
    fi
fi

# ---------------------------------------------------------------- summary
echo
echo "=============================================="
echo " passed: $PASS    failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo " RESULT: OK - environment is set up correctly"
    echo "=============================================="
    exit 0
else
    echo " RESULT: FAILURE - see messages above"
    echo " logs kept in: $WORK"
    echo "=============================================="
    exit 1
fi
