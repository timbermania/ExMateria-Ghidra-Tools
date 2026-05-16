# Ghidra Setup Guide for FFT BATTLE.BIN Reverse Engineering

## Overview

The particle system code at PC `0x801A634C` is in **BATTLE.BIN**, which is a code overlay loaded during battles.

**File:** `&lt;path-to&gt;\fft-extract\BATTLE.BIN`
**Size:** 1,397,096 bytes (1.4 MB)
**Load Address:** 0x80067800 (immediately after main executable)

## Step 1: Create New Ghidra Project

1. Launch Ghidra
2. File → New Project
3. Choose "Non-Shared Project"
4. Name it: `FFT_Battle_Analysis`
5. Location: Somewhere convenient (e.g., `<path-to>\fft-ghidra\`)

## Step 2: Import BATTLE.BIN

1. In the project window, click **File → Import File**
2. Select: `&lt;path-to&gt;\fft-extract\BATTLE.BIN`
3. In the import dialog:

   **Language:** `MIPS:LE:32:default` (MIPS 32-bit Little Endian)

   **IMPORTANT:** Click "Options..." button

4. In the Options dialog, set:
   - **Base Address:** `80067800` (NO 0x prefix in Ghidra!)
   - **Block Name:** `battle_overlay`
   - Leave other options as default

5. Click OK, then OK again to import

## Step 3: Analyze BATTLE.BIN

1. Ghidra will ask if you want to analyze - click **Yes**
2. In the analysis options dialog:
   - **Check:** "Create Address Tables" ✓
   - **Check:** "Decompiler Parameter ID" ✓
   - **Check:** "Non-Returning Functions - Discovered" ✓
   - **Check:** "Subroutine References" ✓
   - Leave others at defaults

3. Click **Analyze**
4. This will take a few minutes

## Step 4: Navigate to Particle System Code

Once analysis completes:

1. Press **G** (or Navigation → Go To...)
2. Enter address: `801a634c`
3. Press Enter

You should see:

```mips
801a634c    lh    a0,0xb0(s7)
801a6350    lh    a1,0xb2(s7)
801a6354    jal   FUN_801a8be0
```

## Step 5: Analyze the Function

Right-click on the instruction at `801a634c` and select:
- **Function → Create Function** (if not already a function)

Or find the function start by scrolling up to the prologue:
- Look for `addiu sp, sp, -0xXX` (stack allocation)
- Look for `sw ra, 0xXX(sp)` (save return address)

## Step 6: Set Up Structures

Create a structure for the particle emitter in Ghidra:

1. Window → Data Type Manager
2. Right-click on `battle_overlay` → Data Type Manager → New → Structure
3. Name it: `ParticleEmitter`
4. Add fields based on our documentation:

| Offset | Type   | Name                    |
|--------|--------|-------------------------|
| 0x00   | byte   | byte_00                 |
| 0x01   | byte   | anim_index              |
| 0x02   | byte   | motion_type_flag        |
| 0x03   | byte   | animation_target_flag   |
| ...    | ...    | ...                     |
| 0xB0   | ushort | particle_count_base     |
| 0xB2   | ushort | particle_count_factor   |
| 0xB4   | ushort | particle_count_mult_1   |
| 0xB6   | ushort | particle_count_mult_2   |

Full structure is 196 bytes (0xC4)

## Step 7: Apply Structure to Registers

When you see code like `lh a0,0xb0(s7)`:

1. Right-click on the function name
2. Edit Function Signature
3. Set parameter types:
   - `void particle_spawn_function(ParticleEmitter* emitter)`

4. In the decompiler, you should see better variable names

## Step 8: Use the Decompiler

1. Window → Decompiler (or press F5 in the listing)
2. You'll see pseudo-C code that's MUCH easier to read than assembly
3. Click on variables to rename them
4. Right-click → Retype Variable to set types

## Verification: Check Your Setup

To verify you have the correct load address:

### Test 1: Check the instruction bytes

At address `801a634c`, you should see bytes: `b0 00 e4 86`

If you see different bytes, the load address is wrong.

### Test 2: Check the function call

At address `801a6354`, there should be a `jal` to `801a8be0`

If the target address is way off, adjust the base address.

### Test 3: Cross-reference with memory dump

In PCSX-Redux when breakpoint hits:
- Check $s7 register value
- It should be pointing to `801C28AC` (Emitter 0 base)
- The code is reading `[$s7 + 0xB0]` which matches offset in our emitter structure

## Verifying the Correct Base Address

The correct base address is **0x80067800** because:

1. **Main executable ends at:** 0x80066800 (from `disassembly.txt`)
2. **BATTLE.BIN loads immediately after** the main executable
3. **Particle code at PC 0x801A634C** is at file offset 0x13EB4C in BATTLE.BIN
4. **Calculation:** 0x801A634C - 0x13EB4C = 0x80067800

If you need to change base address after import:
1. Window → Memory Map
2. Right-click on the memory block → **Set Image Base**
3. Enter new address: `80067800`
4. Click OK, then **Yes** to reanalyze

## Finding Other Particle System Functions

Once you have the spawn function at `801a634c`:

### Find callers:
1. Right-click on function name
2. References → Show References to [function]
3. This shows where the particle spawn is called from

### Find related functions:
- Look for other `jal` calls in the same function
- Check cross-references to nearby functions
- Search for other accesses to offset 0xB0 (particle count)

### Search for emitter structure access:
1. Search → For Scalars
2. Enter `0xB0` (or other offsets)
3. Find all code reading particle_count_base

## Annotating Your Findings

As you reverse engineer:

1. **Rename functions:**
   - Right-click function → Rename Function
   - Example: `FUN_801a634c` → `spawn_particles`

2. **Add comments:**
   - ; key adds comment before line
   - Right-click → Set Comment for detailed notes

3. **Label variables:**
   - Click on `local_XX` variables in decompiler
   - Press L to rename
   - Example: `local_10` → `particle_count`

4. **Create bookmarks:**
   - Right-click → Bookmark
   - Mark important functions for later reference

## Advanced: Finding VFX Load Code

To find where E001.BIN is loaded:

1. Search → Memory → String Search
2. Search for "E001" or "EFFECT"
3. Look for file I/O functions (CD-ROM reads)
4. Trace how VFX data gets into the emitter structures

## Exporting Your Findings

To share or backup your analysis:

1. File → Export Program
2. Choose format (C/C++ for decompiled code)
3. Or: Save Ghidra project (keeps all your annotations)

## Tips for MIPS Reverse Engineering in Ghidra

### Delay Slots
MIPS has **branch delay slots** - the instruction after a branch/jump ALWAYS executes:

```mips
beq   t0, zero, 0x801a6400    # Branch if t0 == 0
addiu t1, t1, 1               # THIS EXECUTES EVEN IF BRANCH TAKEN!
```

Ghidra handles this, but be aware when reading assembly.

### Register Conventions
- `$a0-$a3`: Arguments (first 4 parameters)
- `$v0-$v1`: Return values
- `$s0-$s7`: Saved registers (callee-saved)
- `$t0-$t9`: Temporary registers (caller-saved)
- `$sp`: Stack pointer
- `$ra`: Return address
- `$gp`: Global pointer (FFT uses for static data)

### Common Patterns

**Function Prologue:**
```mips
addiu sp, sp, -0x40    # Allocate 64 bytes of stack
sw    ra, 0x3C(sp)     # Save return address
sw    s0, 0x38(sp)     # Save s0
sw    s1, 0x34(sp)     # Save s1
```

**Function Epilogue:**
```mips
lw    ra, 0x3C(sp)     # Restore return address
lw    s0, 0x38(sp)     # Restore s0
addiu sp, sp, 0x40     # Free stack frame
jr    ra               # Return
```

**Loading 32-bit Constants:**
```mips
lui   t0, 0x801C       # Load upper 16 bits
ori   t0, t0, 0x28AC   # OR lower 16 bits
# Result: t0 = 0x801C28AC (emitter base address!)
```

## Next Steps After Setup

1. **Analyze the particle spawn function** at `801a634c`
   - Understand the loop that spawns each particle
   - Find where position, velocity, color are set

2. **Trace the calculation function** at `801a8be0`
   - See how particle count is computed
   - Check if it uses mult_1 and mult_2 fields

3. **Find motion type handlers**
   - Search for reads of offset 0x02 (motion_type_flag)
   - Find switch/jump table for different motion types

4. **Map all 196 bytes**
   - Find every offset access in BATTLE.BIN
   - Confirm or discover field purposes

5. **Find VFX loader**
   - How E001.BIN is read from CD
   - How it gets parsed into emitter structures

Good luck with your reverse engineering!
