# ghidra_effect_decompile.py
# Ghidra Python (Jython) script for decompiling FFT effect callback code.
#
# Imports an effect binary (CODE section only) at 0x801C2500,
# renames known API functions and globals, decompiles all functions,
# and writes annotated C to an output file.
#
# Usage (headless):
#   analyzeHeadless /tmp/ghidra_effects EffectProject \
#     -import E317_code.bin \
#     -loader BinaryLoader -loader-baseAddr 801C2500 \
#     -processor "MIPS:LE:32:default" \
#     -scriptPath <path-to>/fft-ghidra/tools \
#     -postScript ghidra_effect_decompile.py <path-to>/decompiled/E317.c
#
# Usage (interactive Ghidra):
#   Run from Script Manager after importing effect binary at 0x801C2500
#   Will prompt for output file path.

from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.cmd.label import RenameLabelCmd
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.mem import MemoryBlockType

import os
import sys
import struct

# =============================================================================
# CALLBACK API FUNCTIONS
# External BATTLE.BIN functions called by effect code via JAL
# =============================================================================

CALLBACK_API_FUNCTIONS = [
    # Math / Interpolation
    (0x801A8BE0, "lerp",            "int lerp(int start, int end, int t)"),
    (0x8001BB5C, "rsin",            "int rsin(int angle)"),
    (0x8001BC28, "rcos",            "int rcos(int angle)"),
    (0x801A8834, "cosine_ease",     "int cosine_ease(int start, int end, int t, int duration)"),
    (0x801A8C14, "interp_xyz",      "void interp_xyz(void *emitter, int t, int *out)"),
    (0x801A873C, "vec3_magnitude",  "int vec3_magnitude(int x, int y, int z)"),
    (0x8001D8E8, "ratan2",          "int ratan2(int y, int x)"),
    (0x8002230C, "random",          "int random(int max)"),

    # Particle System
    (0x801A4DE8, "alloc_particle",  "void *alloc_particle(int size, int type)"),
    (0x801A4E9C, "cleanup_sprite_4", "void cleanup_sprite_4(void *ptr)"),
    (0x801A60AC, "emitter_control", "void emitter_control(short effect_idx, short emitter_idx, int frame, void *parent)"),
    (0x801A90D0, "coord_transform", "void coord_transform(void *ptr, int mode, int x, int y)"),

    # GPU Rendering
    (0x80044A60, "get_gpu_buffer",  "void *get_gpu_buffer(void)"),
    (0x80023D44, "gpu_prim_setup",  "void gpu_prim_setup(void *ptr)"),
    (0x80023BB4, "AddPrim",         "void AddPrim(void *ot, void *prim)"),

    # GTE / Matrix
    (0x8001D0A8, "RotMatrix_gte",   "void RotMatrix_gte(void *matrix)"),
    (0x8001D138, "SetRotMatrix",    "void SetRotMatrix(void *matrix)"),
    (0x8001D578, "ApplyMatrixLV",   "void ApplyMatrixLV(void *matrix, void *vec_in, void *vec_out)"),
    (0x8001D658, "SetRotMatrix2",   "void SetRotMatrix2(void *matrix)"),

    # Game State
    (0x8008BF1C, "get_unit_facing", "int get_unit_facing(void)"),
    (0x80183FB4, "get_tile_height", "int get_tile_height(int x, int z)"),
    (0x8008DF48, "get_cursor_pos",  "void get_cursor_pos(int *out)"),

    # Effect System Internal
    (0x801A1288, "resolve_callback", "void *resolve_callback(int id)"),
]

# =============================================================================
# KNOWN GLOBALS
# =============================================================================

KNOWN_GLOBALS = [
    # Effect File Data Pointers
    (0x801BBF88, "effect_data_ptr"),
    (0x801BBF7C, "effect_anim_tbl_ptr"),
    (0x801BACC8, "effect_flags_ptr"),
    (0x801BC0C8, "timeline_section_ptr"),
    (0x801BBF90, "active_effect_list_head"),
    (0x801BBF8C, "animation_table_ptr"),
    (0x801BBF80, "texture_data_ptr"),
    (0x801BBF74, "g_sound_section_ptr"),
    (0x801BC094, "script_bytecode_ptr"),

    # Effect State
    (0x801BF02C, "effect_state_array_base"),
    (0x801C24D0, "current_effect_index"),
    (0x801C24D4, "child_effect_index"),
    (0x801BF000, "current_texture_page"),
    (0x801BAD0C, "effect_context_value"),
    (0x801B67C8, "effect_handler_jump_table"),
    (0x801BBF64, "effect_target_unit"),

    # Camera
    (0x80098A24, "camera_matrix"),

    # Unit Position
    (0x801BADCA, "unit_x_tile"),
    (0x801BADCC, "unit_y_lookup"),
    (0x801BADCE, "unit_z_tile"),

    # Physics
    (0x801B8A40, "gravity_x"),
    (0x801B8A44, "gravity_y"),
    (0x801B8A48, "gravity_z"),
    (0x801B8A4C, "inertia_threshold"),

    # Rendering
    (0x801B9278, "ordering_table_ptr"),
    (0x80045998, "frame_pacing_value"),

    # Line/Primitive State
    (0x801BADE4, "line_count"),
    (0x801BADE8, "line_index_array"),
    (0x801BADEC, "line_frame_counter"),
    (0x801BADF0, "line_pos_x"),
    (0x801BADF2, "line_pos_y"),
    (0x801BADF4, "line_pos_z"),
    (0x801BADF8, "line_time_scale"),

    # Animation State Pool
    (0x801BF00A, "anim_state_free_head"),
    (0x801C24DA, "anim_state_alloc_head"),
    (0x801B9270, "particle_pool_head"),

    # Sprite Buffers
    (0x801CC074, "sprite_buffer_base"),
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_api_stubs(api_functions):
    """Create memory blocks with 'jr ra; nop' stubs for external API functions.

    Groups nearby addresses into memory blocks, writes MIPS 'jr $ra; nop'
    at each function address, then creates and names the functions.
    This makes the decompiler resolve JAL targets to named functions.
    """
    from java.io import ByteArrayInputStream

    # MIPS 'jr $ra' = 0x03E00008, 'nop' = 0x00000000 (little-endian)
    JR_RA = struct.pack("<I", 0x03E00008)
    NOP = struct.pack("<I", 0x00000000)

    mem = currentProgram.getMemory()
    listing = currentProgram.getListing()

    # Group addresses into contiguous blocks (with padding) to minimize
    # the number of memory blocks we create
    sorted_apis = sorted(api_functions, key=lambda x: x[0])

    # Create individual small blocks for each API function
    created = 0
    for addr_int, name, sig in sorted_apis:
        addr = toAddr(addr_int)
        block_name = "stub_%s" % name
        stub_size = 8  # jr ra + nop

        # Check if memory already exists here
        if mem.getBlock(addr) is not None:
            # Memory exists, try to just create/rename function
            func = getFunctionAt(addr)
            if func is None:
                cmd = CreateFunctionCmd(addr)
                cmd.applyTo(currentProgram)
                func = getFunctionAt(addr)
            if func:
                func.setName(name, SourceType.USER_DEFINED)
                print("EXISTING: 0x%08X -> %s" % (addr_int, name))
                created += 1
            continue

        # Create a small memory block with stub code
        stub_bytes = JR_RA + NOP
        stream = ByteArrayInputStream(stub_bytes)

        try:
            block = mem.createInitializedBlock(
                block_name, addr, stream, stub_size,
                ConsoleTaskMonitor(), False
            )
            block.setRead(True)
            block.setExecute(True)
            block.setWrite(False)

            # Disassemble the stub
            disassemble(addr)

            # Create function
            cmd = CreateFunctionCmd(addr)
            if cmd.applyTo(currentProgram):
                func = getFunctionAt(addr)
                if func:
                    func.setName(name, SourceType.USER_DEFINED)
                    print("STUB: 0x%08X -> %s" % (addr_int, name))
                    created += 1
            else:
                print("WARN: Created block but no function at 0x%08X" % addr_int)
        except Exception as e:
            # If block creation fails (overlap etc), fall back to label
            createLabel(addr, name, True)
            print("LABEL (fallback): 0x%08X -> %s (%s)" % (addr_int, name, str(e)))

    return created


def rename_global(addr_int, name):
    """Create or rename a label at the given address."""
    addr = toAddr(addr_int)
    if addr is None:
        return False

    sym = getSymbolAt(addr)
    if sym:
        old = sym.getName()
        if old == name:
            return True
        cmd = RenameLabelCmd(sym, name, SourceType.USER_DEFINED)
        if cmd.applyTo(currentProgram):
            print("GLOBAL: 0x%08X  %s -> %s" % (addr_int, old, name))
            return True
        else:
            print("WARN: Failed to rename 0x%08X" % addr_int)
            return False
    else:
        createLabel(addr, name, True)
        print("GLOBAL: 0x%08X  (new) %s" % (addr_int, name))
        return True


def get_output_path():
    """Get the output file path from script args or prompt."""
    args = getScriptArgs()
    if args and len(args) > 0:
        return args[0]

    # Interactive mode: prompt
    return str(askFile("Save decompiled C to", "Save"))


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("FFT Effect Callback Decompiler")
    print("=" * 70)

    output_path = get_output_path()
    if not output_path:
        print("ERROR: No output path specified")
        return

    # Step 1: Create API function stubs (with actual executable code)
    print("\n--- Creating %d API function stubs ---" % len(CALLBACK_API_FUNCTIONS))
    stub_count = create_api_stubs(CALLBACK_API_FUNCTIONS)

    # Step 2: Rename globals
    print("\n--- Renaming %d globals ---" % len(KNOWN_GLOBALS))
    for addr, name in KNOWN_GLOBALS:
        rename_global(addr, name)

    # Step 3: Find all functions in the effect code region
    # Effect code is at 0x801C2500+, find all functions there
    effect_base = 0x801C2500

    # Always ensure a function exists at the base address.
    # Ghidra auto-analysis may not detect the first function boundary,
    # which is typically the first (and often most important) callback.
    base_addr = toAddr(effect_base)
    if getFunctionAt(base_addr) is None:
        cmd = CreateFunctionCmd(base_addr)
        if cmd.applyTo(currentProgram):
            print("Created entry function at 0x%08X" % effect_base)
        else:
            print("WARNING: Could not create function at base 0x%08X" % effect_base)

    fm = currentProgram.getFunctionManager()
    effect_functions = []

    func_iter = fm.getFunctions(True)  # forward iterator
    while func_iter.hasNext():
        f = func_iter.next()
        addr_long = f.getEntryPoint().getOffset()
        # Include functions in effect code region and API stubs
        if addr_long >= effect_base:
            effect_functions.append(f)

    print("\nFound %d functions in effect code region" % len(effect_functions))

    # Step 4: Decompile
    print("\n--- Decompiling %d functions ---" % len(effect_functions))

    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(currentProgram)

    monitor = ConsoleTaskMonitor()
    output_lines = []

    # Header comment
    output_lines.append("/*")
    output_lines.append(" * Auto-decompiled by ghidra_effect_decompile.py")
    output_lines.append(" * Program: %s" % currentProgram.getName())
    output_lines.append(" * Base address: 0x%08X" % effect_base)
    output_lines.append(" *")
    output_lines.append(" * API functions have been renamed to match fft_callback.h")
    output_lines.append(" * Globals have been renamed to match effect system conventions")
    output_lines.append(" */")
    output_lines.append("")

    # Sort by address
    effect_functions.sort(key=lambda f: f.getEntryPoint().getOffset())

    success_count = 0
    fail_count = 0

    for func in effect_functions:
        addr = func.getEntryPoint()
        name = func.getName()
        print("  Decompiling: %s @ %s" % (name, addr))

        result = decomp.decompileFunction(func, 60, monitor)

        if result and result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            output_lines.append("/* ---- %s @ %s ---- */" % (name, addr))
            output_lines.append(c_code)
            output_lines.append("")
            success_count += 1
        else:
            error_msg = result.getErrorMessage() if result else "null result"
            output_lines.append("/* FAILED: %s @ %s -- %s */" % (name, addr, error_msg))
            output_lines.append("")
            fail_count += 1
            print("  FAILED: %s" % error_msg)

    decomp.dispose()

    # Write output
    parent_dir = os.path.dirname(output_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    with open(output_path, "w") as f:
        f.write("\n".join(output_lines))

    print("\n" + "=" * 70)
    print("COMPLETE: %d succeeded, %d failed" % (success_count, fail_count))
    print("Output: %s" % output_path)
    print("=" * 70)


main()
