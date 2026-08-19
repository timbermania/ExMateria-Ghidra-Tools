#!/usr/bin/env python3
"""Verify BOTH Ghidra text dumps (SCUS + BATTLE.BIN) were exported and are
complete — not just one of them.

Background
----------
`export_ghidra_text.sh` and the full `rebuild_ghidra_from_iso.sh` default to
exporting both programs (`SCUS_942.21` + `BATTLE.BIN`). But a quick partial
command like `export_ghidra_text.sh --listing-only BATTLE.BIN` regenerates
ONLY battle and silently leaves `scus_disassembly.txt` stale or absent —
which is exactly how SCUS went missing (2026-07-01). Nothing complained,
because the missing file just... wasn't there.

Test
----
For each expected program, assert its `<stem>_disassembly.txt`:
  * exists and is non-trivially sized (a truncated/empty export fails),
  * starts at the correct RAM load base,
  * covers its full address range (the last address line is near the top
    of the program's range — catches a truncated export).

Ghidra's export prefixes an address with the program block name
(`scus:` / `battle:`) or `ram:` for a flat mount — all three are accepted.

Exit 0 = both present + complete. Exit 1 = something missing/short/truncated,
with the regen command. SKIP (0) only when the tree isn't set up at all
(no dumps AND no extract), matching test_battle_bin_export_base.py.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FFT_ROM = REPO / "project-assets" / "fft-rom"
EXTRACT = REPO / "project-assets" / "fft-extract"

# stem, load base, minimum top-of-range the last address must reach, min bytes.
# Ranges (2026-07-01 export): scus 0x80010000..0x80066fff, battle
# 0x80067000..0x801bc167. Thresholds sit safely inside those with margin.
PROGRAMS = [
    {"stem": "scus",   "base": 0x80010000, "top_min": 0x80066000, "min_bytes": 2_000_000},
    {"stem": "battle", "base": 0x80067000, "top_min": 0x801b0000, "min_bytes": 10_000_000},
]

ADDR_RE = re.compile(r"(?:ram|scus|battle):([0-9a-fA-F]{8})")


def _first_addr(path: Path):
    with path.open("r", errors="replace") as f:
        for line in f:
            m = ADDR_RE.search(line)
            if m:
                return int(m.group(1), 16)
    return None


def _last_addr(path: Path):
    """Scan the tail for the last address line (fast for 80 MB files)."""
    size = path.stat().st_size
    with path.open("rb") as f:
        f.seek(max(0, size - 65536))
        tail = f.read().decode("latin-1", errors="replace")
    matches = ADDR_RE.findall(tail)
    if matches:
        return int(matches[-1], 16)
    # Dense disasm always has matches in the tail; fall back to a full scan.
    last = None
    with path.open("r", errors="replace") as f:
        for line in f:
            m = ADDR_RE.search(line)
            if m:
                last = int(m.group(1), 16)
    return last


def main() -> int:
    dumps = {p["stem"]: FFT_ROM / f"{p['stem']}_disassembly.txt" for p in PROGRAMS}

    if not any(d.exists() for d in dumps.values()) and not EXTRACT.exists():
        print("SKIP: no dumps and no project-assets/fft-extract "
              "(populate per SETUP.md, then run the export)", file=sys.stderr)
        return 0

    regen = ("  fft-ghidra/tools/export_ghidra_text.sh            "
             "# both programs (SCUS + BATTLE)")
    failures = []

    for p in PROGRAMS:
        stem, base, top_min, min_bytes = (
            p["stem"], p["base"], p["top_min"], p["min_bytes"])
        dis = dumps[stem]

        if not dis.exists():
            failures.append(f"{stem}_disassembly.txt MISSING")
            continue

        sz = dis.stat().st_size
        if sz < min_bytes:
            failures.append(
                f"{stem}_disassembly.txt too small ({sz} bytes < {min_bytes})")
            continue

        first = _first_addr(dis)
        if first != base:
            failures.append(
                f"{stem}_disassembly.txt starts at "
                f"0x{(first or 0):08X}, expected base 0x{base:08X}")
            continue

        last = _last_addr(dis)
        if last is None or last < top_min:
            failures.append(
                f"{stem}_disassembly.txt looks truncated — last address "
                f"0x{(last or 0):08X} < 0x{top_min:08X}")
            continue

        print(f"PASS: {stem}_disassembly.txt  "
              f"0x{first:08X}..0x{last:08X}  ({sz:,} bytes)")

    if failures:
        print("\nFAIL: incomplete Ghidra export —", file=sys.stderr)
        for msg in failures:
            print(f"  - {msg}", file=sys.stderr)
        print("\nRegenerate BOTH dumps (do not pass a single program name):\n"
              f"{regen}", file=sys.stderr)
        return 1

    print("\nPASS: both SCUS + BATTLE dumps present and complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
