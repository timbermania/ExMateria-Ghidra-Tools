# -*- coding: utf-8 -*-
# @category FFT.EffectSoundParity
# @runtime Jython
#
# ghidra_apply_effect_sound_annotations.py
#
# Push the effect-sound-parity investigation findings into the Ghidra
# project: rename auto-generated DAT_xxxx labels to semantic names,
# rename anonymous opcode FUN_xxxxxxxx handlers to op_<hex>_<role>, and
# add plate/pre comments at the load-bearing PCs surfaced by the
# investigations.
#
# IDEMPOTENT: every change is gated on a check against the current
# program state. Labels are renamed only when the current name still has
# the DAT_/FUN_/LAB_ auto-prefix or doesn't match the target. Comments
# carry a `[effect-sound-parity v2]` marker; we skip if the marker is
# already present in the existing comment.
#
# Usage (headless):
#   /opt/ghidra/support/analyzeHeadless project-assets fft-ghidra \
#     -process SCUS_942.21 -noanalysis \
#     -scriptPath research/tools \
#     -postScript ghidra_apply_effect_sound_annotations.py
#
# This script only touches SCUS_942.21 (all the new findings live in
# SCUS memory 0x80010000..0x80030000). BATTLE.BIN isn't affected.
#
# Scope (this version):
#   1. OCTAVE_SHIFT_LOOKUP label at 0x80028FE8
#   2. SEMITONE_LOOKUP     label at 0x80029060
#   3. PITCH_LOOKUP_TABLE  label at 0x800290D8 + plate comment about
#      the actual table size (12288 u16 entries) -- exceeds the 3072
#      entries that the original Godot transcription assumed
#   4. op_ec_lfo_arm_subslot2 at 0x80016974 (was FUN_80016974)
#   5. op_ef_clear_subslot2   at 0x80016AF0 (was LAB_80016AF0)
#   6. Pre-comments at:
#        0x80013D2C  -- chan+0x92 init writer (env-multiplier seed)
#        0x80015488  -- s4=1 (LFO period_reset gate trigger)
#        0x800157AC  -- LFO sub-slot period_reset loop body entry
#        0x80017424  -- midi_to_spu_pitch_lookup plate comment
#
# Extend this script when new findings warrant new annotations; keep
# the [effect-sound-parity v2] marker consistent so re-runs stay clean.

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressFactory

MARKER = "[effect-sound-parity v2]"

prog = currentProgram
listing = prog.getListing()
symtab = prog.getSymbolTable()
af = prog.getAddressFactory()


def addr(hex_str):
    return af.getAddress(hex_str)


def rename_label(addr_hex, new_name, allow_overwrite_prefixes=("DAT_", "FUN_", "LAB_", "SUB_")):
    """Rename the primary symbol at addr_hex to new_name, but only if
    the existing name is auto-generated (matches one of the prefixes).
    Returns True if renamed, False if skipped."""
    a = addr(addr_hex)
    sym = symtab.getPrimarySymbol(a)
    if sym is None:
        print("[annotate] %s: no primary symbol; creating label %s" % (addr_hex, new_name))
        symtab.createLabel(a, new_name, SourceType.USER_DEFINED)
        return True
    current = sym.getName()
    if current == new_name:
        print("[annotate] %s: already named %s (skip)" % (addr_hex, new_name))
        return False
    if not current.startswith(allow_overwrite_prefixes):
        # Non-auto name already there -- don't overwrite a human/user
        # name. Add a secondary label instead so the new_name is
        # discoverable too. Check first to keep this idempotent.
        for s in symtab.getSymbols(a):
            if s.getName() == new_name:
                print("[annotate] %s: secondary label %s already present (skip)"
                      % (addr_hex, new_name))
                return False
        print("[annotate] %s: existing user name %s; adding %s as secondary"
              % (addr_hex, current, new_name))
        symtab.createLabel(a, new_name, SourceType.USER_DEFINED)
        return True
    print("[annotate] %s: renaming %s -> %s" % (addr_hex, current, new_name))
    sym.setName(new_name, SourceType.USER_DEFINED)
    return True


def set_comment(addr_hex, comment_type, body):
    """Set a comment at addr_hex, but only if the existing comment
    doesn't already contain our MARKER. Body is wrapped with the marker
    on a leading line. comment_type: 'PLATE' / 'PRE' / 'POST' / 'EOL'."""
    a = addr(addr_hex)
    cu = listing.getCodeUnitAt(a)
    if cu is None:
        # No code unit (raw bytes / undefined). Try via getCommentAddress-
        # tolerant API.
        existing = listing.getComment(_comment_type_const(comment_type), a) or ""
    else:
        existing = cu.getComment(_comment_type_const(comment_type)) or ""
    if MARKER in existing:
        print("[annotate] %s: %s comment already marked (skip)" % (addr_hex, comment_type))
        return False
    new_text = MARKER + "\n" + body
    if cu is not None:
        cu.setComment(_comment_type_const(comment_type), new_text)
    else:
        listing.setComment(a, _comment_type_const(comment_type), new_text)
    print("[annotate] %s: set %s comment" % (addr_hex, comment_type))
    return True


def _comment_type_const(name):
    from ghidra.program.model.listing import CodeUnit
    return {
        "PRE":   CodeUnit.PRE_COMMENT,
        "POST":  CodeUnit.POST_COMMENT,
        "EOL":   CodeUnit.EOL_COMMENT,
        "PLATE": CodeUnit.PLATE_COMMENT,
        "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
    }[name]


# ----------------------------------------------------------------------
# 1-3: Lookup table labels
# ----------------------------------------------------------------------
rename_label("0x80028FE8", "OCTAVE_SHIFT_LOOKUP")
set_comment("0x80028FE8", "PLATE", (
    "FFT pitch-lookup OCTAVE_SHIFT_LOOKUP -- 128 bytes, u8.\n"
    "Used by midi_to_spu_pitch_lookup (FUN_80017424) as\n"
    "  octave_shift = 6 - OCTAVE_SHIFT_LOOKUP[(a0 & 0x7FFF) >> 8]\n"
    "Indices 0..107 follow the linear pattern\n"
    "  floor(idx / 12)  (so 0..8 cycle through 12 entries each)\n"
    "Indices 117..119 = 0 (padding); 120..127 = 0,1,2,3,4,5,6,7.\n"
    "Mirrored in smd-player/scripts/pitch_table.gd::OCTAVE_SHIFT_LOOKUP;\n"
    "any drift between this ROM data and that constant is caught by\n"
    "research/effect_alignment/probes/probe_constants_invariant.lua."
))

rename_label("0x80029060", "SEMITONE_LOOKUP")
set_comment("0x80029060", "PLATE", (
    "FFT pitch-lookup SEMITONE_LOOKUP -- 128 bytes, u8.\n"
    "Used by midi_to_spu_pitch_lookup (FUN_80017424) as\n"
    "  table_idx = SEMITONE_LOOKUP[(a0 & 0x7FFF) >> 8] * 256 + (a0 & 0xFF)\n"
    "Indices 0..107 follow `idx % 12` (the obvious linear pattern).\n"
    "WARNING: the tail entries DO NOT continue linearly:\n"
    "  [112..116] = 4,5,6,7,8         (5 normal entries)\n"
    "  [117..120] = 0,0,0,0           (padding)\n"
    "  [121,123,125,127] = 32         (** the surprise **)\n"
    "  [122,124,126]     = 2,4,6       (alternating normal)\n"
    "Mirrored in smd-player/scripts/pitch_table.gd::SEMITONE_LOOKUP. The\n"
    "first 8 bytes of SEMITONE_LOOKUP physically alias the last 8 bytes\n"
    "of OCTAVE_SHIFT_LOOKUP (both label 0x80029060..0x80029067). See\n"
    "PITCH_TABLE_TRUNCATION.md for the 2026-05-16 transcription-bug fix\n"
    "where Godot had 1,3,5,7 at the surprise indices instead of 32,32,32,32."
))

rename_label("0x800290D8", "PITCH_LOOKUP_TABLE")
set_comment("0x800290D8", "PLATE", (
    "FFT pitch-lookup PITCH_LOOKUP_TABLE -- u16 entries, byte-addressed.\n"
    "Used by midi_to_spu_pitch_lookup (FUN_80017424) as\n"
    "  result = TABLE[(SEMITONE_LOOKUP[oct] * 256 + (a0 & 0xFF)) * 2]\n"
    "  result is then shifted by (6 - OCTAVE_SHIFT_LOOKUP[oct]).\n"
    "Logical layout: 256 u16 entries per semitone bin. The formula\n"
    "reaches up to semitone=32 (SEMITONE_LOOKUP's max value), so the\n"
    "logically-required size is 33 * 256 = 8448 u16 entries = 16896\n"
    "bytes. The observable contiguous data in RAM extends out to at\n"
    "least 12288 u16 entries (24576 bytes); Godot mirrors the full\n"
    "12288 in smd-player/scripts/pitch_table.gd::TABLE so the byte-for-\n"
    "byte invariant in probe_constants_invariant.lua matches."
))

# ----------------------------------------------------------------------
# 4-5: Opcode handler renames
# ----------------------------------------------------------------------
rename_label("0x80016974", "op_ec_lfo_arm_subslot2")
set_comment("0x80016974", "PLATE", (
    "SMD opcode 0xEC handler -- arms LFO sub-slot 2 (chan+0x120..0x13F)\n"
    "with mode 2 (pan-LFO) and HARDCODED callback_idx=3\n"
    "(pitch_accum_callback / triangle). 3 params (p0, p1, p2):\n"
    "  - p0 = inner_reload (sub+0x12)\n"
    "  - p1 = step base; step_source = pitch_lfo_step_calc(p1<<24, p0, 3)\n"
    "  - p2 = outer-delay reload (sub+0x16)\n"
    "Sets sub+0x1A = 0x100 (depth_reload, FIXED), sub+0x1C = 2 (mode),\n"
    "sub+0x1D = 3 (callback_idx), sub+0x1E = 3 (active_dir bits 0x1+0x2).\n"
    "Sibling: FUN_80016A14 (op_ed) does the same but with callback_idx\n"
    "from (p2 & 0xF). Disarmed by 0xEF (op_ef_clear_subslot2, LAB_80016AF0)."
))

rename_label("0x80016AF0", "op_ef_clear_subslot2")
set_comment("0x80016AF0", "PLATE", (
    "SMD opcode 0xEF handler -- disarms LFO sub-slot 2 by clearing bit\n"
    "0x1 of chan+0x13E (sub+0x1E active flag). 0 params.\n"
    "  lhu  v0, 0x13e(a2)\n"
    "  andi v0, v0, 0xfffe   ; clear bit 0x1\n"
    "  sh   v0, 0x13e(a2)\n"
    "Counterpart to op_ec / op_ed which set the same bit."
))

# ----------------------------------------------------------------------
# 6: Pre-comments at load-bearing PCs
# ----------------------------------------------------------------------
set_comment("0x80013D2C", "PRE", (
    "chan+0x92 env-multiplier seed writer. Stores `(0x6000 * instr_byte)\n"
    ">> 7` where instr_byte is per-sound-id (from the engine table at\n"
    "*DAT_80032A00 + halfword(s5+0xc) + sound_id). Fires once per\n"
    "channel during FUN_80013B20's per-channel init loop.\n"
    "Sound-id -> instr_byte -> chan_92 examples:\n"
    "  cure_4 (sid 4): 0x60 -> (0x6000*0x60)>>7 = 0x4800 = 18432\n"
    "  protect (sid 9): 0x80 -> (0x6000*0x80)>>7 = 0x6000 = 24576\n"
    "Godot mirrors via channel_state.gd::chan_92_value, orchestrator\n"
    "plumbs the per-effect value via render_effect_sound's --chan92=\n"
    "flag (sourced from diag_chan_92_writers.jsonl::new_value)."
))

set_comment("0x80015488", "PRE", (
    "s4 = 1 -- Note-with-KON_ARM gate. Reached only when:\n"
    "  - a Note byte (< 0x80) is dispatched this tick, AND\n"
    "  - chan_word_0 bit 0x400 (KON_ARM) was set BEFORE the per-tick\n"
    "    clear (i.e. a Rest / duration-tick / effect-load handler\n"
    "    armed the next KON in a prior tick).\n"
    "s4 is checked at PC 0x80015718 to fire the LFO sub-slot\n"
    "period_reset at LAB_800157AC (clears acc, resets countdown, clears\n"
    "dir bits 0x4/0x8). Without this gate firing, mid-effect LFO swap-\n"
    "path direction toggles drift (protect_no_music chan_8a sign-flip).\n"
    "Godot mirrors the gate at dispatcher.gd::cadence_body line ~1099\n"
    "(`note_dispatched and (s2_snapshot & CHAN0_KON_ARM) != 0`) and\n"
    "fires _apply_lfo_period_reset(channel) at the same point."
))

set_comment("0x800157AC", "PRE", (
    "LFO sub-slot period_reset loop body. Iterates 3 sub-slots\n"
    "(chan+0xFE, chan+0x11E, chan+0x13E = sub-slot 0/1/2's active+dir\n"
    "flags). Gate: `(flags & 0x1) && (flags & 0x2)` -- active AND\n"
    "first-segment. When the gate passes, the reset:\n"
    "  - sub+0x04 = 0           (accumulator clear)\n"
    "  - sub+0x10 = 1           (countdown reset to 1)\n"
    "  - sub+0x14 = sub+0x16    (delay_counter reload)\n"
    "  - sub+0x18 = sub+0x1A    (depth reload)\n"
    "  - chan_word_0 |= 0x100   (CHAN0_VOL_PRESTAGE)\n"
    "  - sub+0x1E &= ~0xC       (clear dir bits 0x4 and 0x8)\n"
    "Outer gate at PC 0x80015718 is `s4 != 0` -- set at PC 0x80015488.\n"
    "Godot port: dispatcher.gd::_apply_lfo_period_reset.\n"
    "See CHAN_8A_PAN_LFO_SIGN_FLIP_INVESTIGATION.md for the protect_\n"
    "no_music bug this loop fixes on the FFT side."
))

set_comment("0x80017424", "PLATE", (
    "midi_to_spu_pitch_lookup -- encodes a (signed s16) midi*256+fine\n"
    "value into an SPU pitch-register value.\n"
    "  v1 = a0 & 0x7FFF              (mask off sign + upper)\n"
    "  octave_index = v1 >> 8        (logical shift)\n"
    "  fine_byte = a0 & 0xFF\n"
    "  semitone = SEMITONE_LOOKUP[octave_index]      (0x80029060)\n"
    "  octave_shift_raw = OCTAVE_SHIFT_LOOKUP[octave_index]  (0x80028FE8)\n"
    "  table_idx = semitone * 256 + fine_byte\n"
    "  base = PITCH_LOOKUP_TABLE[table_idx]          (0x800290D8)\n"
    "  shift = 6 - octave_shift_raw\n"
    "  return (s32)((s16)base >> shift)              if shift >= 0\n"
    "         (s32)((s16)base << (-shift))           if shift <  0\n"
    "Caller (FUN_80017118 PC 0x80017340..0x80017368) feeds\n"
    "  a0 = sign_extend_s16(chan+0x82 + chan+0x88 + slot+0xA2)\n"
    "and stores the masked 14-bit result to chan+0x46 (pitch_staging).\n"
    "Note: NEGATIVE inputs are NOT clamped; the `andi 0x7FFF` mask treats\n"
    "them as positive 0..32767 for octave_index. Godot's pitch_table.gd\n"
    "originally had a defensive `if adjusted < 0: adjusted = 0` clamp\n"
    "that was removed in commit d890cc6c to match this semantic."
))

print("[annotate] done. Re-run is safe (idempotent on MARKER + label-name checks).")
