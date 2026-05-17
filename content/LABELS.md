# FFT Ghidra label table — apply probe-confirmed names to BATTLE.BIN

Every entry in `labels_battle_bin.tsv` comes from a Lua probe whose
**value-level output pairs bit-exactly** between PCSX-Redux and Godot on
`cure_no_music`. Confirmed PAIR status lives in
`research/effect_alignment/last_run/probe_pairs.json`. That means we can
state with high confidence what each FFT function does — the probe
captured arguments, return values and side-effects, and the Godot port
reproduces them exactly.

## What this contains

`labels_battle_bin.tsv` — tab-separated, six columns:

| column | meaning |
|---|---|
| `pc` | hex address (e.g. `0x8001B628`) |
| `kind` | `function` = rename + plate comment; `label` = primary user label + pre-comment |
| `name` | new Ghidra-safe identifier (e.g. `spu_write_voice_pitch`) |
| `pair_status` | `PAIR` (bit-exact) / `PAIR_DRIFT` (values match, ±cadence drift only) / `FAIL_COUNT` (values match, row count differs) / `FAIL_VALUES` (some rows diff) / `-` (not directly probed) |
| `plate_comment` | multi-line function description (literal `\n` → newline). Used for `kind=function` only. |
| `pre_comment` | single-line annotation pinned to that exact PC. Use `-` for blank. |

Coverage as of branch `effect-sound-parity` commit `bae7d761`: 51
entries — every probe under `research/effect_alignment/probes/probe_*.lua`
plus the supporting infrastructure (`async_commit_walker_irq`,
`spu_io_write_helper`, pitch-LFO mode-1 / mode-2 callbacks).

## Applying labels in Ghidra

The wrapper `fft-ghidra/tools/apply_all_renames.sh` runs labels
automatically as the final tier after LOW and HIGH renames. Use the
direct forms below only for one-off / GUI work.

### GUI (one-off)

1. Open BATTLE.BIN in Ghidra.
2. Window → Script Manager.
3. Add `fft-ghidra/tools/` to your script paths if not already there.
4. Run `fft_apply_labels.py`. When prompted, point it at
   `fft-ghidra/content/labels_battle_bin.tsv`.
5. Save the program.

### Headless (direct)

```bash
analyzeHeadless <ghidra-project-dir> <project-name> \
    -process "BATTLE.BIN" \
    -scriptPath fft-ghidra/tools \
    -postScript fft_apply_labels.py \
      "<absolute-path-to>/fft-ghidra/content/labels_battle_bin.tsv"
```

Drop `-readOnly` if you want the renames persisted (default in this
script is to write; use the GUI's "save program" or set the
appropriate `analyzeHeadless` flags).

The script is **idempotent** — re-running with no TSV changes produces
zero edits. Adding a new entry and re-running picks up only that entry.

## Priority vs. LOW/HIGH renames

Labels are the highest tier — they run after `apply_renames_low.py` and
`apply_renames_high.py` in the wrapper, so on the ~40 addresses where a
label entry overlaps a rename entry, the label wins. The rename
applicators don't emit `OVERRIDE:` lines for label-tier wins (the label
applicator runs as a separate analyzeHeadless invocation and doesn't see
the prior rename state); inspect the wrapper's run.log to see what
happened at each tier.

## Adding new entries

After a new probe pairs PAIR (or PAIR_DRIFT with explanation), append a
row to `labels_battle_bin.tsv`:

1. The probe's BP_ADDR is the `pc`.
2. If `pc` is a function entry (check
   `research/effect_sound/ghidra_dump/BATTLE_BIN/manifest.tsv`): use
   `kind=function`, write a complete plate comment.
3. Otherwise: use `kind=label`, leave plate empty (`-`), put a one-line
   annotation in `pre_comment`.
4. Set `pair_status` from the latest run's `probe_pairs.json`.
5. Re-run the applicator.

## Why this exists

Before: each researcher had a fresh `FUN_8001B628` in their Ghidra
instance and had to re-derive what it did by reading both the disasm
and the probe file. Now the TSV is the single source of truth; the
applicator pushes it into Ghidra.

The TSV also lives in git, so renames don't drift between machines —
the disassembly and decompilation exports under
`project-assets/fft-rom/` will continue to use the new names after
re-export, keeping `battle_decompilation.c` greppable by semantic name.
