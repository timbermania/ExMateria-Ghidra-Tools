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
| `labels_battle_bin.tsv` | Probe-confirmed BATTLE.BIN names + per-row plate/pre comments. |
| `comments_<binary>.jsonl` | Free-text plate/pre/post comments (multi-line, JSON-escaped). Currently `comments_scus.jsonl`. |

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
| `fft_apply_labels.py` | Applier for `labels_battle_bin.tsv` (Jython). |
| `apply_comments.py` | Generic JSONL-driven comments applier (Jython). |
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
| `ghidra_force_disassemble_battle.py` | Force-disassemble known data-tagged code ranges. |

### Content application order (later wins on overlap)

1. **LOW renames** — `content/renames_low*.tsv`.
2. **HIGH renames** — `content/renames_high*.tsv`. Emits `OVERRIDE:` log lines.
3. **Labels** (BATTLE.BIN) — `content/labels_battle_bin.tsv` (name + plate/pre cols).
4. **Comments** (per binary) — `content/comments_<binary>.jsonl`.

### `docs/`

- `QUICK_START.md` — fastest path to a working project.
- `SETUP_GUIDE.md` — comprehensive setup, alternatives, troubleshooting.

## Requirements

- Ghidra 11.x (`GHIDRA_HOME` pointing at the install, e.g. `/opt/ghidra`).
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

## Provenance

This is published from the fft-project monorepo. The canonical copy
lives there; this repo is a mirror for sharing.
