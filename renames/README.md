# Two-Tier Ghidra Renames

Symbol renames for the `fft-ghidra` Ghidra project, split by confidence tier.

## Files

| File | Purpose |
|------|---------|
| `renames_low.tsv` | LOW-confidence (hypothesis) renames. Applied **first**. |
| `renames_high.tsv` | HIGH-confidence (validated) renames. Applied **second**, wins on overlap. |
| `renames_high_<domain>.tsv` | Optional sub-files per subsystem (e.g. `renames_high_sound.tsv`). Auto-loaded alongside the base HIGH file. Same applies to LOW. |
| `apply_renames_low.py` | Jython post-script — loads every `renames_low*.tsv` in this dir. |
| `apply_renames_high.py` | Jython post-script — loads every `renames_high*.tsv` in this dir. Logs `OVERRIDE:` when it overrides a LOW name. |
| `_renames_common.py` | Shared parser / symbol resolution / DEL handling. |
| `../tools/apply_all_renames.sh` | Wrapper: runs LOW then HIGH across all 14 imported programs. |

The apply scripts glob `renames_<tier>*.tsv` in this directory, so you can split a tier into multiple domain-specific files without editing any code. Files within a tier load alphabetically; the primary `renames_<tier>.tsv` is loaded first.

## TSV schema

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

## How to add a rename

1. Decide tier:
   - **HIGH** — you have behavioral evidence (decomp confirmation, parity match against a reimplementation, wiki citation).
   - **LOW** — plausible from static analysis but unvalidated. Prefix description with `Hyp:`.
2. Append a row to the appropriate `.tsv`.
3. Run the wrapper:
   ```bash
   fft-ghidra/tools/apply_all_renames.sh
   ```
   or for a single program:
   ```bash
   fft-ghidra/tools/apply_all_renames.sh BATTLE.BIN
   ```
4. Commit the .tsv change.

## Promoting LOW → HIGH

Cut the row from `renames_low.tsv`, paste into `renames_high.tsv`, drop the `Hyp:` prefix from the description, and add the validation evidence. Re-run the wrapper. The next run's log will emit:
```
OVERRIDE: 0x801a634c low='Hyp_Foo' -> high='Foo'
```

## Removing a rename you no longer trust

Two options:

- **If both tiers had it**: delete from both. Next run leaves the symbol at whatever default Ghidra last analyzed (`FUN_*`/`DAT_*`).
- **If only HIGH had it and you want it explicitly reverted on rerun**: change the `type` column to `DEL` and the name to `-`. The apply script will call `sym.delete()` to revert any USER_DEFINED name at that address.

## Conflict / override behavior

- LOW runs first; HIGH runs second.
- HIGH applying a different name to an address LOW already renamed → `OVERRIDE:` log line, HIGH wins.
- HIGH `DEL` row at an address LOW renamed → `OVERRIDE-DEL:` log line, symbol reverts.
- Same name in both tiers at same address → idempotent (no log).

## SKIP_MID_INSTR — when a rename can't be applied

If a `FN`-typed row points at an address that Ghidra's auto-analyzer placed *inside* an existing function (rather than at the start), the row is logged as `SKIP_MID_INSTR` and skipped. This usually means the analyzer drew function boundaries differently from the original symbol map — common on raw-binary imports where there's no debug info.

Two ways to fix:

- **In the GUI**: navigate to the address, right-click the wrong-boundaried function, "Edit Function" → adjust entry point. Re-run the wrapper.
- **Headless via `fix_function_boundaries.py`**: hardcode the `(correct_addr, name)` pair into the `FIXUPS` list at the top of that script, then run:

  ```bash
  /opt/ghidra/support/analyzeHeadless <ghidra-project-dir> fft-ghidra \
      -process <PROGRAM_NAME> -noanalysis \
      -scriptPath fft-ghidra/renames \
      -postScript fix_function_boundaries.py
  ```

  The script removes the wrong-boundaried function and recreates one at the correct address, then setName-s it. Idempotent. After running, rerun `apply_all_renames.sh` so the matching TSV row finds the now-correct function.

## Run output

`run.log` accumulates per-program output. Useful greps:

```bash
grep "^\[LOW\] FN "  fft-ghidra/renames/run.log | wc -l   # LOW fn renames applied
grep "^\[HIGH\] FN " fft-ghidra/renames/run.log | wc -l   # HIGH fn renames applied
grep "OVERRIDE:"      fft-ghidra/renames/run.log           # what got promoted
grep "SKIP_"          fft-ghidra/renames/run.log           # bad rows (mid-instr, not code, etc.)
```

## Headers required

Both apply scripts use Jython 2.7 (the Ghidra default for `.py` in Ghidra 12 is now PyGhidra; Jython is opt-in via the runtime tag):

```python
# -*- coding: utf-8 -*-
# @runtime Jython
```

## Out of scope

Data structure (`.h`) definitions and `ApplyDataTypeCmd` field-naming live elsewhere — not in this rename system. Once the rename layer settles, a follow-up tier of structure files may layer on top via the same TSV-driven mechanism.
