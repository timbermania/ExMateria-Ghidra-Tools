# fft-ghidra content

All Ghidra-applied **content** for the `fft-ghidra` project — symbol
names, label/function annotations, and free-text plate/pre/post
comments. The **tooling** that reads these files (the Jython appliers
and the shell wrapper) lives in `../tools/`.

## Files

| File | What it carries |
|---|---|
| `renames_low.tsv` | LOW-confidence (hypothesis) symbol renames. |
| `renames_low_<domain>.tsv` | Optional domain add-ons (e.g. `renames_low_sound.tsv`). Auto-loaded alongside the base LOW file. |
| `renames_high.tsv` | HIGH-confidence (validated) symbol renames. |
| `renames_high_<domain>.tsv` | Optional domain add-ons (e.g. `renames_high_sound.tsv`). |
| `labels_battle_bin.tsv` | Probe-confirmed names + plate/pre comments for BATTLE.BIN. See `LABELS.md`. |
| `comments_<binary>.jsonl` | Plate/pre/post comment bodies, one JSON object per line. Currently `comments_scus.jsonl`. |
| `run.log` | Latest output of the wrapper. Not committed. |

The Jython appliers (`../tools/apply_renames_{low,high}.py`,
`../tools/fft_apply_labels.py`, `../tools/apply_comments.py`) read these
files; the wrapper `../tools/apply_all_renames.sh` runs them in tier
order. See `../tools/apply_all_renames.sh` for the canonical pipeline.

## Application order (later tier wins on overlap)

1. **LOW renames** — every `renames_low*.tsv`.
2. **HIGH renames** — every `renames_high*.tsv`. Emits `OVERRIDE:` log lines when overriding a LOW name.
3. **Labels** (BATTLE.BIN only) — `labels_battle_bin.tsv`.
4. **Comments** (per binary) — `comments_<binary>.jsonl`.

The label and comment tiers are separate analyzeHeadless invocations
from the rename tiers, so they don't see prior tiers' state — they
just last-write-wins by ordering.

## Rename TSV schema

Tab-separated, comments start with `#`, blank lines ignored:

```
address  binary  type  name  description
```

| Column | Notes |
|--------|-------|
| `address` | Hex with `0x` prefix, lowercase preferred (`0x801a634c`). |
| `binary` | `BATTLE`, `SCUS`, `E001`..`E511`, `*` (any program), or comma-separated (`BATTLE,SCUS`). |
| `type` | `FN` = function (creates if needed; skips mid-instruction). `GL` = global label. `DEL` = revert any USER_DEFINED name at this address back to `FUN_*`/`DAT_*`. |
| `name` | The new symbol name. For `DEL` rows use `-` as a placeholder. |
| `description` | Freeform. Convention: "what + confidence evidence". For LOW, prefix with `Hyp:`. **No literal tabs** in this column. |

The HIGH/LOW appliers glob `renames_<tier>*.tsv` in this directory, so
you can split a tier into multiple domain-specific files without
touching code. Files within a tier load alphabetically; the primary
`renames_<tier>.tsv` is loaded first.

## Comments JSONL schema

One JSON object per line. Blank lines and lines starting with `#` are
ignored. Schema:

```json
{"pc": "0x80028FE8", "kind": "PLATE", "text": "first line\nsecond line"}
```

| Field | Notes |
|-------|-------|
| `pc` | Hex address with `0x` prefix. |
| `kind` | `PLATE`, `PRE`, `POST`, `EOL`, or `REPEATABLE`. |
| `text` | Comment body. Use JSON's `\n` escape for newlines. |
| `binary` | (Optional) Program name. If set, applier skips when `currentProgram.getName()` differs — handy for one JSONL spanning multiple programs. |

Each applied comment is tagged with a leading marker line so re-runs
are idempotent. The applier also recognises the legacy marker
`[effect-sound-parity v2]` from the retired `ghidra_apply_effect_sound_annotations.py`
script, so programs previously annotated by that script don't get
double-commented.

## Common operations

### Add a rename
1. Decide tier: **HIGH** (behavioural evidence) or **LOW** (static-analysis guess; prefix description with `Hyp:`).
2. Append a row to the appropriate `.tsv`.
3. Re-run `../tools/apply_all_renames.sh`.
4. Commit the `.tsv` change.

### Promote LOW → HIGH
Cut the row from `renames_low.tsv`, paste into `renames_high.tsv`, drop
the `Hyp:` prefix, add validation evidence. Next run logs:
```
OVERRIDE: 0x801a634c low='Hyp_Foo' -> high='Foo'
```

### Remove a rename you no longer trust
- **Both tiers had it**: delete from both. Next run leaves Ghidra's default `FUN_*`/`DAT_*`.
- **Only HIGH had it, want it explicitly reverted on rerun**: change `type` to `DEL`, `name` to `-`. The applier calls `sym.delete()`.

### Add a comment
1. Append a JSON line to `comments_<binary>.jsonl` (create the file if it doesn't exist).
2. If new binary, add a `case` in `../tools/apply_all_renames.sh`'s comments tier.
3. Re-run the wrapper.

## SKIP_MID_INSTR — when a rename can't be applied

If a `FN`-typed row points at an address that Ghidra's auto-analyzer
placed *inside* an existing function (rather than at the start), the
row is logged as `SKIP_MID_INSTR` and skipped. Usually means the
analyzer drew function boundaries differently from the original symbol
map — common on raw-binary imports.

Two fixes:

- **GUI**: navigate to the address, right-click the wrong-boundaried
  function, "Edit Function" → adjust entry point. Re-run the wrapper.
- **Headless via `../tools/fix_function_boundaries.py`**: hardcode the
  `(correct_addr, name)` pair into the `FIXUPS` list at the top of that
  script, then run:

  ```bash
  /opt/ghidra/support/analyzeHeadless <ghidra-project-dir> fft-ghidra \
      -process <PROGRAM_NAME> -noanalysis \
      -scriptPath fft-ghidra/tools \
      -postScript fix_function_boundaries.py
  ```

  The script removes the wrong-boundaried function and recreates one
  at the correct address, then `setName`-s it. Idempotent. After
  running, rerun `apply_all_renames.sh` so the matching TSV row finds
  the now-correct function.

## Run output

`run.log` (in this directory) accumulates the latest run's output.
Useful greps:

```bash
grep "^\[LOW\] FN "          fft-ghidra/content/run.log | wc -l   # LOW fn renames applied
grep "^\[HIGH\] FN "         fft-ghidra/content/run.log | wc -l   # HIGH fn renames applied
grep "OVERRIDE:"             fft-ghidra/content/run.log           # what got promoted
grep "SKIP_"                 fft-ghidra/content/run.log           # bad rows
grep -E "0x[0-9a-fA-F]+ +(function|label)" fft-ghidra/content/run.log   # label tier
grep "applied$"              fft-ghidra/content/run.log           # comments tier
```

## Out of scope

Data structure (`.h`) definitions and `ApplyDataTypeCmd` field-naming
live elsewhere — not in this content system. Once the rename layer
settles, a follow-up tier of structure files may layer on top via the
same content-driven mechanism.
