# fft-ghidra

Tools for reverse-engineering Final Fantasy Tactics (PSX) with
[Ghidra](https://ghidra-sre.org/). A reproducible pipeline that takes
the extracted ROM, builds a labelled Ghidra project, and emits text
disassembly/decompilation that other tooling can grep over.

## What's here

```
content/      All data the appliers apply: TSVs, JSONL comments, schemas docs.
tools/        All implementation: Jython postscripts + shell wrappers.
docs/         User-facing setup guide and quick-start.
```

The split is content vs tooling: open `content/` to *read* what's
applied to the Ghidra project; open `tools/` to see *how* it's applied.

### `content/`

| File | What it carries |
|---|---|
| `renames_low.tsv` + `renames_low_<domain>.tsv` | LOW-confidence symbol renames (hypotheses). |
| `renames_high.tsv` + `renames_high_<domain>.tsv` | HIGH-confidence renames (validated). Covers sound system + particle/VFX effect system. |
| `labels_<binary>.tsv` | Probe-confirmed names + per-row plate/pre comments for one program (e.g. `labels_scus.tsv`). |
| `comments_<binary>.jsonl` | Free-text plate/pre/post comments (multi-line, JSON-escaped). Currently `comments_scus.jsonl`. |
| `types_<domain>.h` | C struct/typedef definitions parsed by Ghidra's CParser into the program's data type manager (e.g. `types_particle_emitter.h`). |

See `content/README.md` for the TSV/JSONL schemas and conflict rules,
and `content/LABELS.md` for the labels TSV in detail.

### `tools/`

| Script | Purpose |
|---|---|
| `bootstrap_ghidra_project.sh` | First-time setup: create project, import binaries, apply content. |
| `rebuild_ghidra_from_iso.sh` | End-to-end rebuild from an extracted ISO. |
| `apply_all_renames.sh` | Apply the full content pipeline (LOW → HIGH → labels → comments). |
| `export_ghidra_text.sh` | Re-export `{scus,battle}_{disassembly.txt,decompilation.c}`. |
| `fix_battle_bin_disassembly.sh` | Apply BATTLE.BIN overlay + force-disassemble fixes. |
| `apply_renames_low.py` / `apply_renames_high.py` | Tier appliers for the rename TSVs (Jython). |
| `fft_apply_labels.py` | Applier for `labels_<binary>.tsv` (Jython). |
| `apply_comments.py` | Generic JSONL-driven comments applier (Jython). |
| `apply_types.py` | C-header importer (Jython, wraps `CParserUtils.parseHeaderFiles`). |
| `_renames_common.py` | Shared TSV parse / symbol resolution for the rename appliers. |
| `fix_function_boundaries.py` | One-off helper for `SKIP_MID_INSTR` rows. |
| `fft_verify_load.py` | Sanity-check that a program loaded at expected addresses. |
| `ghidra_export_listing.py` | Plain-text listing exporter (Jython). |
| `ghidra_effect_decompile.py` | Per-function decompiler for an effect's code range. |
| `ghidra_full_decompile.py` | Bulk decompile every function in `currentProgram`. |
| `ghidra_list_programs.py` | Enumerate programs in a Ghidra project. |
| `ghidra_add_battle_overlay.py` / `_secondary.py` | Add the BATTLE.BIN secondary-load overlay block. |
| `ghidra_add_runtime_install_80150.py` | Overlay the runtime-installed code region at `0x80150000`. |
| `ghidra_disassemble_secondary.py` | Disassemble every 4-byte boundary in the overlay. |
| `ghidra_force_disassemble_battle.py` | Force-disassemble known data-tagged code ranges (BATTLE.BIN). |
| `ghidra_force_disassemble_scus.py` | Force-disassemble SCUS code the analyzer left as `??` (GTE `rotate_vector`/`svector_pack`, reached only via fn-pointers). Run BEFORE `apply_all_renames.sh`. |

### Content application order (later wins on overlap)

1. **LOW renames** — `content/renames_low*.tsv`.
2. **HIGH renames** — `content/renames_high*.tsv`. Emits `OVERRIDE:` log lines.
3. **Labels** (per binary) — `content/labels_<binary>.tsv` (name + plate/pre cols).
4. **Comments** (per binary) — `content/comments_<binary>.jsonl`.
5. **Types** (per binary) — `content/types_<domain>.h` (C struct/typedef defs).

### `docs/`

- `QUICK_START.md` — fastest path to a working project.
- `SETUP_GUIDE.md` — comprehensive setup, alternatives, troubleshooting.

## Requirements

- Ghidra 11.x or 12.x with PyGhidra (`GHIDRA_HOME` pointing at the install,
  e.g. `/opt/ghidra`; the pipeline drives `support/pyghidraRun`).
- An extracted FFT (PSX) ISO. The scripts expect `SCUS_942.21`,
  `BATTLE.BIN`, and the `EFFECT/E*.BIN` set.
- Python 3 for the host-side wrappers; the Jython scripts run inside
  Ghidra's headless analyser.

## Typical workflow

```sh
# 1. Full pipeline — import + structural fixes + content (all tiers).
GHIDRA_HOME=/opt/ghidra ./tools/rebuild_ghidra_from_iso.sh

# Or step by step:
./tools/bootstrap_ghidra_project.sh        # import + apply_all_renames
./tools/fix_battle_bin_disassembly.sh      # BATTLE.BIN overlay + force-disasm
./tools/apply_all_renames.sh               # re-apply content (covers the overlay)
./tools/export_ghidra_text.sh              # regenerate text exports
```

## Text exports & address citations

Exports live at `project-assets/fft-rom/{scus,battle}_{disassembly.txt,decompilation.c}`:
SCUS covers `0x80010000–0x80066FFF`, BATTLE.BIN covers `0x80067000+`.
Regenerate with `tools/export_ghidra_text.sh`.

**Cite addresses, not line numbers** — `*_disassembly.txt` line numbers shift
across regenerations, so `0x80015874` (or `ram:80015874`) is the stable
reference. Live RAM is always ground truth.

**BATTLE.BIN base-address gotcha:** prior to 2026-06-20 the bootstrap script
imported BATTLE.BIN at the wrong base `0x80067800`. If your local
`battle_disassembly.txt` was exported before that fix, every BATTLE.BIN RAM
address in it is shifted `+0x800` from reality — regenerate via
`tools/rebuild_ghidra_from_iso.sh` before trusting any address citation.
`hacktics_disassembly.txt` was already correct.

## Surfacing a function the auto-analyzer left undefined

Sometimes the analyzer leaves a known code range as undefined data (`??`) or an
unnamed `FUN_xxxx`. To surface it (e.g. the vitals-bar renderer
`draw_vitals_bars @0x801352BC`): add its range to `RANGES` in
`ghidra_force_disassemble_battle.py`, add a `renames_high.tsv` entry, then
re-run the affected pipeline steps against the local `fft-ghidra` project
(under `project-assets/`):

```sh
GHIDRA_HOME=/opt/ghidra ./tools/fix_battle_bin_disassembly.sh  # force-D the new RANGES + auto-analysis creates fns
GHIDRA_HOME=/opt/ghidra ./tools/apply_all_renames.sh           # apply LOW/HIGH renames + labels + comments
GHIDRA_HOME=/opt/ghidra ./tools/export_ghidra_text.sh          # regenerate the text dumps
```

For **SCUS** the equivalent is `ghidra_force_disassemble_scus.py` (no shell
wrapper — invoke it directly, then re-apply + re-export):

```sh
GHIDRA_HOME=/opt/ghidra /opt/ghidra/support/analyzeHeadless \
  "$PWD/../project-assets" fft-ghidra -process SCUS_942.21 -noanalysis \
  -scriptPath tools -postScript ghidra_force_disassemble_scus.py
GHIDRA_HOME=/opt/ghidra ./tools/apply_all_renames.sh SCUS_942.21
GHIDRA_HOME=/opt/ghidra ./tools/export_ghidra_text.sh --listing-only SCUS_942.21
```

Note: a function reached only through a function pointer can *decompile*
correctly (the decompiler disassembles on-the-fly) while still showing `??`
bytes in the listing — that's the tell that its instructions were never
committed and it needs force-D. Known remaining SCUS gap of this kind:
`build_rotation_matrix @0x8001D658` and the adjacent GTE-helper cluster.

**Close the Ghidra GUI first** — the headless run locks the project (and only
one headless run at a time — concurrent runs `LockException`). The regenerated
`battle_disassembly.txt` is **not committed** (it lives beyond the gitignored
`project-assets` symlink, ~106 MB) — only the script/TSV inputs are tracked.

## Ghidra 12.1.2 (+): use `pyghidraRun -H`, not `analyzeHeadless`

On the current install (Ghidra 12.1.2, root-owned `/opt/ghidra`),
`analyzeHeadless` routes `.py` postscripts to **PyGhidra** and dies with *"Ghidra
was not started with PyGhidra"* — the Jython `.py` provider is shadowed and can't
be disabled without root. Run the Jython postscripts through **`pyghidraRun -H`**
instead (PyGhidra initialises → `currentProgram` set, flat API + `from java.io
import …` work). The first invocation offers to create the settings-dir venv;
symlink the existing one (`ln -sfn ~/.config/ghidra/ghidra_12.1_DEV/venv
~/.config/ghidra/ghidra_12.1.2_DEV/venv`) so the bundled pyghidra/jpype wheels
install offline.

⚠ Two caveats for the appliers: (1) the wrappers (`apply_all_renames.sh`,
`export_ghidra_text.sh`) hardcode `analyzeHeadless` — invoke the postscripts
directly under `pyghidraRun -H`, or shim `$ANALYZE`. (2) `apply_renames_*.py`
use `execfile` (Python 2) which breaks under PyGhidra's CPython — use the
PyGhidra-native `wapply_world.py` (reads a `renames_*.tsv`, creates fns/labels +
plate comments) as the applier until the Jython path is restored.

## The WORLD.BIN overlay (formation / roster / unit-detail screen)

The formation "sort list" + unit-detail **Status** screen renders in the
**WORLD.BIN** overlay (disc file `project-assets/fft-extract/WORLD/WORLD.BIN`, a
flat image loaded byte-for-byte at **base `0x800E0000`**; `file_off = RAM −
0x800E0000`). It's **not** in the SCUS/BATTLE flat disasm. Import it once:

```sh
export GHIDRA_INSTALL_DIR=/opt/ghidra
/opt/ghidra/support/pyghidraRun -H "$PWD/../project-assets" fft-ghidra \
  -import "$PWD/../project-assets/fft-extract/WORLD/WORLD.BIN" \
  -processor MIPS:LE:32:default -loader BinaryLoader -loader-baseAddr 0x800E0000
# apply the WORLD renames + re-export the greppable listing
/opt/ghidra/support/pyghidraRun -H "$PWD/../project-assets" fft-ghidra -process WORLD.BIN \
  -noanalysis -scriptPath tools -postScript wapply_world.py
FFT_OUT_DIR="$PWD/../project-assets/fft-rom" /opt/ghidra/support/pyghidraRun -H \
  "$PWD/../project-assets" fft-ghidra -process WORLD.BIN -noanalysis -readOnly \
  -scriptPath tools -postScript ghidra_export_listing.py   # -> world_disassembly.txt
```

Names live in `content/renames_high_world.tsv`. RE record + field maps:
`research/working_documents/FORMATION_SCREEN.md` §15.10–15.13.

## Provenance

This is published from the fft-project monorepo. The canonical copy
lives there; this repo is a mirror for sharing.
