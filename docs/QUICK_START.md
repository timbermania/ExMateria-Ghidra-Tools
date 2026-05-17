# Quick Start: Reverse Engineering FFT Particles in Ghidra

## TL;DR Setup (5 minutes)

1. **Open Ghidra** → New Project → `FFT_Battle_Analysis`

2. **Import File:**
   - File: `&lt;path-to&gt;\fft-extract\BATTLE.BIN`
   - Language: `MIPS:LE:32:default`
   - **Options → Base Address:** `80067800` (no 0x!)

3. **Analyze:** Click "Yes" when prompted, use default options

4. **Import Structure:** *(or just run `tools/apply_all_renames.sh` — types tier handles this automatically)*
   - File → Parse C Source
   - Select: `fft-ghidra/content/types_particle_emitter.h`

5. **Navigate to particle code:**
   - Press **G**
   - Enter: `801a634c`

## What You'll See

```mips
801a634c    lh    a0,0xb0(s7)        ← Loading particle_count_base
801a6350    lh    a1,0xb2(s7)        ← Loading particle_count_factor
801a6354    jal   FUN_801a8be0       ← Calling calculation function
```

## Your First Steps

1. **Find the function start** (scroll up from 801a634c):
   - Look for `addiu sp, sp, -0xXX`
   - Right-click → Create Function

2. **Open Decompiler** (Window → Decompiler or press F5):
   - See readable pseudo-C code
   - Much easier than raw assembly!

3. **Rename variables:**
   - Click on `local_XX` in decompiler
   - Press **L** to rename
   - Example: `local_10` → `particle_count`

4. **Set function signature:**
   - Right-click function → Edit Function Signature
   - Change to: `void spawn_particles(ParticleEmitter *emitter)`
   - Now `emitter->particle_count_base` appears in decompiler!

## Key Addresses to Investigate

| Address    | What                          | Why Important                       |
|------------|-------------------------------|-------------------------------------|
| 0x801A634C | Particle spawn entry          | Where you are now                   |
| 0x801A8BE0 | Particle count calculation    | Formula: base × factor × mult1 × mult2 |
| 0x801C28AC | Emitter 0 data (runtime)      | Your breakpoint data address        |

## Finding More Code

**Who calls this function?**
- Right-click function name → References → Show References to

**What else is nearby?**
- Window → Function Call Graph
- Shows all related functions visually

**Search for emitter field access:**
- Search → Memory → Search All
- Search for bytes: `b0 00` (the load offset)

## Export Your Findings

**Get decompiled C code:**
- File → Export Program
- Format: C/C++
- Save as: `battle_decompiled.c`

**Save your project:**
- File → Save Project
- Keeps all your annotations, comments, renamed functions

## Keyboard Shortcuts

| Key   | Action                |
|-------|-----------------------|
| **G** | Go to address         |
| **L** | Rename label/variable |
| **;** | Add comment           |
| **[** | Back in history       |
| **]** | Forward in history    |
| **F5**| Open decompiler       |

## Verification Checklist

✓ At address 801a634c, bytes should be: `b0 00 e4 86`
✓ Instruction should decode to: `lh a0, 0xb0(s7)`
✓ Next instruction at 801a6350: `lh a1, 0xb2(s7)`
✓ Function call at 801a6354 should target: `801a8be0`

If any don't match, check your base address (should be `80067800`).

## Need Help?

See full guide: `GHIDRA_SETUP_GUIDE.md`
