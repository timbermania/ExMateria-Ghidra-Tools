# fft-ghidra

Tools for reverse-engineering Final Fantasy Tactics (PSX) with
[Ghidra](https://ghidra-sre.org/). A reproducible pipeline that takes
the extracted ROM, builds a labelled Ghidra project, and emits text
disassembly/decompilation that other tooling can grep over.

## What's here

```
tools/        Jython postscripts + shell wrappers (analyzeHeadless drivers)
renames/      Three-tier symbol/label TSVs + applier scripts (LOW, HIGH, labels)
docs/         Setup guide and quick-start
```

### `tools/`

| Script | Purpose |
|---|---|
| `bootstrap_ghidra_project.sh` | First-time setup: create project, import binaries, apply renames |
| `rebuild_ghidra_from_iso.sh` | End-to-end rebuild from an extracted ISO |
| `apply_all_renames.sh` | Apply low/high two-tier renames across every imported program |
| `export_ghidra_text.sh` | Re-export `{scus,battle}_{disassembly.txt,decompilation.c}` |
| `fix_battle_bin_disassembly.sh` | Apply BATTLE.BIN overlay + force-disassemble fixes |
| `fft_verify_load.py` | Sanity-check that a Ghidra program loaded at the expected addresses |
| `ghidra_export_listing.py` | Plain-text listing exporter (Jython) |
| `ghidra_effect_decompile.py` | Per-function decompiler for an effect's code range |
| `ghidra_full_decompile.py` | Bulk decompile every function in `currentProgram` |
| `ghidra_list_programs.py` | Enumerate programs in a Ghidra project |
| `ghidra_add_battle_overlay.py` | Add the BATTLE.BIN secondary-load overlay block |
| `ghidra_add_battle_secondary.py` | Variant: secondary block at the second load address |
| `ghidra_add_runtime_install_80150.py` | Overlay the runtime-installed code region at `0x80150000` |
| `ghidra_disassemble_secondary.py` | Disassemble every 4-byte boundary in the overlay |
| `ghidra_force_disassemble_battle.py` | Force-disassemble known data-tagged code ranges |
| `ghidra_apply_effect_sound_annotations.py` | Apply the SMD/SPU effect-sound annotation set |

### `renames/`

Three-tier symbol pipeline applied in order — later tiers override
earlier ones on the same address:

1. **LOW** (`renames_low*.tsv`) — hypothesised names from static analysis.
2. **HIGH** (`renames_high*.tsv`) — validated names with behavioural
   evidence. Covers both the sound system and the particle/VFX effect
   system. Domain add-ons (e.g. `renames_high_sound.tsv`) are
   auto-loaded alongside the base files.
3. **Labels** (`labels_battle_bin.tsv`) — probe-confirmed names with
   bit-exact parity between PCSX-Redux and the Godot port. Currently
   BATTLE.BIN-only. Includes plate comments and per-PC annotations
   beyond what the rename schema carries.

`apply_all_renames.sh` runs all three tiers in sequence. See
`renames/README.md` for the rename schema and `renames/LABELS.md` for
the label schema and priority semantics.

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
# 1. Full pipeline — import + structural fixes + LOW/HIGH/labels.
GHIDRA_HOME=/opt/ghidra ./tools/rebuild_ghidra_from_iso.sh

# Or step by step:
./tools/bootstrap_ghidra_project.sh        # import + LOW + HIGH
./tools/fix_battle_bin_disassembly.sh      # BATTLE.BIN overlay + force-disasm
./tools/apply_all_renames.sh               # LOW + HIGH + labels (covers the overlay)
./tools/export_ghidra_text.sh              # regenerate text exports
```

## Provenance

This is published from the fft-project monorepo. The canonical copy
lives there; this repo is a mirror for sharing.
