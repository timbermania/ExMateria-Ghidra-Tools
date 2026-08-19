# -*- coding: utf-8 -*-
# @category FFT
# @runtime Jython
#
# apply_comments.py -- Apply PLATE / PRE / POST / EOL / REPEATABLE comments
# from a JSONL content file to currentProgram.
#
# JSONL row schema (one comment per line):
#   {"pc": "0x80028FE8", "kind": "PLATE", "text": "...with \\n newlines..."}
#
# Optional fields:
#   "binary": program name (e.g. "SCUS_942.21"). When set, the row is skipped
#             unless currentProgram.getName() matches -- handy for one JSONL
#             that spans multiple programs.
#
# Idempotent: every applied comment is tagged with MARKER on its leading line.
# Re-runs that see the marker already present skip the row. LEGACY_MARKERS are
# also recognised as "already applied" so we don't double-comment programs
# previously processed by older scripts (e.g. ghidra_apply_effect_sound_annotations.py).
#
# Usage (headless): normally invoked via fft-ghidra/tools/apply_all_renames.sh
# as the final tier. Direct invocation:
#   analyzeHeadless <projectDir> <projectName> \
#       -process SCUS_942.21 -noanalysis \
#       -scriptPath fft-ghidra/tools \
#       -postScript apply_comments.py \
#         "<absolute>/fft-ghidra/content/comments_scus.jsonl"
#
# Usage (GUI): Window -> Script Manager -> run apply_comments.py and pass
# the JSONL path when prompted (via askFile).

import hashlib
import json
import os

from ghidra.program.model.listing import CodeUnit

# Our marker carries a content fingerprint: "[fft-comments h=<hash>]". The hash
# is computed from the SOURCE text, so idempotency compares the recorded marker
# (which round-trips as plain ASCII) rather than the comment body (which Ghidra
# may normalize on store) -- robust + self-healing on edits.
MARKER_PREFIX = "[fft-comments"
MARKER_BARE = "[fft-comments]"            # legacy pre-hash marker (still recognized)
LEGACY_MARKERS = ("[effect-sound-parity v2]",)


def content_marker(body):
    h = hashlib.md5(body.encode("utf-8")).hexdigest()[:10]
    return "%s h=%s]" % (MARKER_PREFIX, h)

KIND_CONST = {
    "PRE":        CodeUnit.PRE_COMMENT,
    "POST":       CodeUnit.POST_COMMENT,
    "EOL":        CodeUnit.EOL_COMMENT,
    "PLATE":      CodeUnit.PLATE_COMMENT,
    "REPEATABLE": CodeUnit.REPEATABLE_COMMENT,
}

args = getScriptArgs()
if len(args) >= 1:
    jsonl_path = args[0]
else:
    f = askFile("Select comments JSONL", "Apply")
    jsonl_path = f.getAbsolutePath()

if not os.path.exists(jsonl_path):
    print("ERROR: JSONL not found: %s" % jsonl_path)
    raise SystemExit(1)

prog = currentProgram
if prog is None:
    print("ERROR: no currentProgram")
    raise SystemExit(1)

listing = prog.getListing()
af = prog.getAddressFactory()

print("=" * 70)
print("FFT comment applicator")
print("Program: %s" % prog.getName())
print("JSONL:   %s" % jsonl_path)
print("=" * 70)


def parse_addr(pc):
    s = pc.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return af.getAddress(s)


def get_existing(a, const):
    cu = listing.getCodeUnitAt(a)
    if cu is not None:
        return cu, (cu.getComment(const) or "")
    return None, (listing.getComment(const, a) or "")


def set_new(a, const, body):
    cu, _ = get_existing(a, const)
    text = content_marker(body) + "\n" + body
    if cu is not None:
        cu.setComment(const, text)
    else:
        listing.setComment(a, const, text)


n_applied = 0
n_skipped_marked = 0
n_skipped_wrong_program = 0
n_error = 0

f = open(jsonl_path)
try:
    for raw_line in f:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except Exception as e:
            print("  SKIP malformed: %r (%s)" % (line[:80], e))
            n_error += 1
            continue
        pc = row.get("pc")
        kind = row.get("kind", "PRE")
        text = row.get("text", "")
        binary = row.get("binary")
        if binary and binary != prog.getName():
            n_skipped_wrong_program += 1
            continue
        if kind not in KIND_CONST:
            print("  %s  SKIP unknown kind %r" % (pc, kind))
            n_error += 1
            continue
        const = KIND_CONST[kind]
        a = parse_addr(pc)
        _, existing = get_existing(a, const)
        first_line = existing.split("\n", 1)[0] if existing else ""
        # Idempotent: skip when our fingerprint already matches the source text.
        if first_line == content_marker(text):
            print("  %s  %-5s  SKIP (marked)" % (pc, kind))
            n_skipped_marked += 1
            continue
        is_ours = first_line.startswith(MARKER_PREFIX)
        # Preserve foreign legacy-tool annotations (not managed by this script).
        if not is_ours and any(m in existing for m in LEGACY_MARKERS):
            print("  %s  %-5s  SKIP (legacy)" % (pc, kind))
            n_skipped_marked += 1
            continue
        action = "updated" if is_ours else "applied"
        set_new(a, const, text)
        print("  %s  %-5s  %s" % (pc, kind, action))
        n_applied += 1
finally:
    f.close()

print()
print("=" * 70)
print("Summary: applied=%d  skipped_marked=%d  skipped_other_program=%d  errors=%d"
      % (n_applied, n_skipped_marked, n_skipped_wrong_program, n_error))
print("=" * 70)
