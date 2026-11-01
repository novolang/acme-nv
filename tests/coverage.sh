#!/usr/bin/env bash
# tests/coverage.sh — the measured line coverage over `src/`, merged
# across the suites.
#
# `novo test --cov` measures one suite file at a time, and a suite's
# percentage counts the suite's own lines as well as the package's.  No
# single number it prints is the one `docs/publishing.md`
# § Test coverage asks for.  This merges the per-suite LCOV and reports
# `src/` alone, which is what a release is measured on.
#
# Run from anywhere:  bash tests/coverage.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/.." && pwd)"
NOVO="${NOVO:-$HOME/.novo/bin/novo}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/acme-nv-cov.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

for suite in "$PKG"/tests/*_tests.nv; do
  base="$(basename "$suite" .nv)"
  ( cd "$PKG" && NOVO_LEAK_CHECK=0 timeout 1800 "$NOVO" test "tests/$base.nv" \
      --cov --report=lcov ) >"$WORK/$base.log" 2>&1
  if [ -f "$PKG/_novo/$base.lcov.info" ]; then
    cp "$PKG/_novo/$base.lcov.info" "$WORK/"
  else
    echo "  ✗ $base — no LCOV written; see $WORK/$base.log"
    exit 1
  fi
done

python3 - "$WORK" "$PKG" <<'PY'
import collections, glob, os, sys

work = sys.argv[1]
pkg = os.path.realpath(sys.argv[2])
cov = collections.defaultdict(dict)
for path in glob.glob(os.path.join(work, '*.lcov.info')):
    current = None
    for line in open(path):
        line = line.strip()
        if line.startswith('SF:'):
            current = line[3:]
        elif line.startswith('DA:'):
            n, hits = line[3:].split(',')[:2]
            n, hits = int(n), int(hits)
            cov[current][n] = cov[current].get(n, 0) + hits

def excused(path):
    """Lines excused by a `cov: skip` marker: the next code line and the lines indented deeper."""
    out = set()
    lines = open(path).read().split('\n')
    for i, text in enumerate(lines):
        if 'cov: skip' in text and text.strip().startswith('//'):
            j = i + 1
            while j < len(lines) and (lines[j].strip() == '' or lines[j].strip().startswith('//')):
                j += 1
            if j >= len(lines):
                continue
            indent = len(lines[j]) - len(lines[j].lstrip())
            out.add(j + 1)
            k = j + 1
            while k < len(lines) and (lines[k].strip() == '' or len(lines[k]) - len(lines[k].lstrip()) > indent):
                out.add(k + 1)
                k += 1
    return out

total = covered = 0
print('')
for path in sorted(cov):
    if not os.path.realpath(path).startswith(pkg + os.sep + 'src' + os.sep):
        continue
    skip = excused(path)
    lines = {n: v for n, v in cov[path].items() if n not in skip}
    hit = sum(1 for v in lines.values() if v > 0)
    missed = sorted(n for n, v in lines.items() if v == 0)
    total += len(lines)
    covered += hit
    print('  %-20s %3d/%-3d  %s' % (
        os.path.basename(path), hit, len(lines),
        'uncovered: ' + ' '.join(str(n) for n in missed) if missed else '100%'))
pct = 100.0 * covered / total if total else 0.0
print('')
print('  src/ total: %d/%d lines — %.1f%%' % (covered, total, pct))
sys.exit(0 if covered == total else 1)
PY
