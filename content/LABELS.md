# FFT Ghidra label tables — apply probe-confirmed names per binary

Every entry in `labels_<binary>.tsv` comes from a Lua probe whose
**value-level output pairs bit-exactly** between PCSX-Redux and Godot
on `cure_no_music`. Confirmed PAIR status lives in
`research/effect_alignment/last_run/probe_pairs.json`. That means we
can state with high confidence what each FFT function does — the
probe captured arguments, return values and side-effects, and the
Godot port reproduces them exactly.

## Files

One TSV per target program. Each file targets a single program's
memory map; cross-binary rows fail silently as `WARN: no code unit`.

| File | Target program |
|------|----------------|
| `labels_scus.tsv` | `SCUS_942.21` (the boot exec; addresses 0x80010000..0x80066FFF) |
| `labels_battle_bin.tsv` *(none yet)* | `BATTLE.BIN` (overlay loaded at 0x80067800+) |

The wrapper `../tools/apply_all_renames.sh` maps program name to the
right TSV via a `case` in its labels tier. Add more cases as new
per-binary label files appear.

## TSV schema

Tab-separated, six columns; comments start with `#`, blank lines OK:

| column | meaning |
|---|---|
| `pc` | hex address (e.g. `0x8001B628`) |
| `kind` | `function` = rename + plate comment; `label` = primary user label + pre-comment |
| `name` | new Ghidra-safe identifier (e.g. `spu_write_voice_pitch`) |
| `pair_status` | `PAIR` (bit-exact) / `PAIR_DRIFT` (values match, ±cadence drift only) / `FAIL_COUNT` (values match, row count differs) / `FAIL_VALUES` (some rows diff) / `-` (not directly probed) |
| `plate_comment` | multi-line function description (literal `\n` → newline). Used for `kind=function` only. |
| `pre_comment` | single-line annotation pinned to that exact PC. Use `-` for blank. |

## Applying labels in Ghidra

The wrapper `../tools/apply_all_renames.sh` runs labels automatically
as the third tier after LOW and HIGH renames. Use the direct forms
below only for one-off / GUI work.

### GUI (one-off)

1. Open the target program (e.g. SCUS_942.21) in Ghidra.
2. Window → Script Manager.
3. Add `fft-ghidra/tools/` to your script paths if not already there.
4. Run `fft_apply_labels.py`. When prompted, point it at the matching
   `fft-ghidra/content/labels_<binary>.tsv`.
5. Save the program.

### Headless (direct)

```bash
analyzeHeadless <ghidra-project-dir> <project-name> \
    -process "SCUS_942.21" \
    -scriptPath fft-ghidra/tools \
    -postScript fft_apply_labels.py \
      "<absolute-path-to>/fft-ghidra/content/labels_scus.tsv"
```

Drop `-readOnly` if you want the renames persisted (default in this
script is to write; use the GUI's "save program" or set the
appropriate `analyzeHeadless` flags).

The script is **idempotent** — re-running with no TSV changes produces
zero edits. Adding a new entry and re-running picks up only that entry.

## Priority vs. LOW/HIGH renames

Labels are tier 3 — they run after `apply_renames_low.py` and
`apply_renames_high.py` in the wrapper, so on addresses where a label
entry overlaps a rename entry, the label wins. The rename applicators
don't emit `OVERRIDE:` lines for label-tier wins (the label applicator
runs as a separate analyzeHeadless invocation and doesn't see the
prior rename state); inspect the wrapper's `run.log` to see what
happened at each tier.

## Adding new entries

After a new probe pairs PAIR (or PAIR_DRIFT with explanation):

1. Pick (or create) the right per-binary TSV — `labels_<binary>.tsv`.
   If creating a new file, add a case to the wrapper's labels tier.
2. The probe's BP_ADDR is the `pc`. It must live inside the target
   program's memory map.
3. If `pc` is a function entry (check
   `research/effect_sound/ghidra_dump/BATTLE_BIN/manifest.tsv`): use
   `kind=function`, write a complete plate comment.
4. Otherwise: use `kind=label`, leave plate empty (`-`), put a
   one-line annotation in `pre_comment`.
5. Set `pair_status` from the latest run's `probe_pairs.json`.
6. Re-run the wrapper.

## Why this exists

Before: each researcher had a fresh `FUN_8001B628` in their Ghidra
instance and had to re-derive what it did by reading both the disasm
and the probe file. Now the TSVs are the single source of truth; the
applicator pushes them into Ghidra.

The TSVs also live in git, so renames don't drift between machines —
the disassembly and decompilation exports under
`project-assets/fft-rom/` will continue to use the new names after
re-export, keeping `battle_decompilation.c` and `scus_decompilation.c`
greppable by semantic name.
