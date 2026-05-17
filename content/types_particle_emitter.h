/*
 * FFT Particle System Structures - Minimal Ghidra Import Version
 *
 * Import: File -> Parse C Source -> Select this file
 * Documentation: See key_documents/STRUCTURE_DEFINITIONS.md
 */

typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef signed short   int16_t;
typedef unsigned int   uint32_t;
typedef signed int     int32_t;

/* ParticleAnimState - 36 bytes */
struct ParticleAnimState {
    uint16_t pool_prev_index;         // 0x00
    uint16_t pool_next_index;         // 0x02
    uint16_t reserved_04;             // 0x04
    uint16_t flags;                   // 0x06
    int16_t  sprite_offset_x;         // 0x08
    int16_t  sprite_offset_y;         // 0x0A
    int16_t  render_position_x;       // 0x0C
    int16_t  render_position_y;       // 0x0E
    int16_t  render_position_z;       // 0x10
    int16_t  screen_rotation_angle;   // 0x12
    uint8_t  depth_mode;              // 0x14
    uint8_t  padding_15;              // 0x15
    uint16_t frame_timer;             // 0x16
    int32_t *sequence_data_ptr;       // 0x18
    uint16_t frame_counter;           // 0x1C
    uint8_t  sprite_variant_offset;   // 0x1E
    uint8_t  sprite_frame_index;      // 0x1F
    void    *sprite_data_ptr;         // 0x20
};

/* Particle - Runtime instance */
struct Particle {
    struct Particle *prev;            // 0x00
    struct Particle *next;            // 0x04
    int16_t  inertia;                 // 0x08
    int16_t  weight;                  // 0x0A
    int32_t  position_x;              // 0x0C
    int32_t  position_y;              // 0x10
    int32_t  position_z;              // 0x14
    int32_t  velocity_x;              // 0x18
    int32_t  velocity_y;              // 0x1C
    int32_t  velocity_z;              // 0x20
    int32_t  acceleration_x;          // 0x24
    int32_t  acceleration_y;          // 0x28
    int32_t  acceleration_z;          // 0x2C
    int32_t  drag_x;                  // 0x30
    int32_t  drag_y;                  // 0x34
    int32_t  drag_z;                  // 0x38
    int16_t  target_x;                // 0x3C
    int16_t  target_y;                // 0x3E
    int16_t  target_z;                // 0x40
    int16_t  lifetime_counter;        // 0x42
    uint8_t  unknown_44;              // 0x44
    uint8_t  homing_curve_index;      // 0x45
    uint8_t  color_r_curve_index;     // 0x46
    uint8_t  color_g_curve_index;     // 0x47
    uint8_t  color_b_curve_index;     // 0x48
    uint8_t  unknown_49;              // 0x49
    int16_t  homing_strength;         // 0x4A
    uint16_t motion_flags;            // 0x4C
    uint16_t behavior_flags;          // 0x4E
    uint16_t anim_frame_counter;      // 0x50
    uint8_t  child_emitter_on_death;  // 0x52
    uint8_t  child_emitter_mid_life;  // 0x53
    struct ParticleAnimState *anim_state; // 0x54
};

/* EffectState - 248 bytes (0xF8) */
struct EffectState {
    int16_t  next_effect_index;       // 0x00
    int16_t  effect_index;            // 0x02
    int16_t  parent_effect_index;     // 0x04
    int16_t  script_position;         // 0x06
    int32_t *script_data_ptr;         // 0x08
    int16_t  child_effect_indices[4]; // 0x0C
    int16_t  script_regs[4];          // 0x14
    int16_t  active_particle_count;   // 0x1C
    uint16_t flags;                   // 0x1E
    int16_t  frame_counter;           // 0x20
    /* Common fields (same in P1 and P2): */
    uint8_t  callback_state[4];       // 0x22: Callback slot state (0=inactive, 1=active, 3=ending)
    uint8_t  effect_target_index;     // 0x26: Current target index
    uint8_t  unknown_27;              // 0x27: Unknown
    /* Pattern-specific fields - use EffectState_P1 or _P2 for typed access: */
    uint8_t  pattern_data[168];       // 0x28-0xCF: Differs between P1 and P2
    struct Particle *particle_list_head; // 0xD0
    void    *callback_ptrs[4];        // 0xD4
    void    *sprite_ptrs[4];          // 0xE4
    void    *current_callback_ptr;    // 0xF4
};

/* EffectState_P1 - For Pattern 1 functions (op_process_timeline_frame) */
struct EffectState_P1 {
    int16_t  next_effect_index;       // 0x00
    int16_t  effect_index;            // 0x02
    int16_t  parent_effect_index;     // 0x04
    int16_t  script_position;         // 0x06
    int32_t *script_data_ptr;         // 0x08
    int16_t  child_effect_indices[4]; // 0x0C
    int16_t  script_regs[4];          // 0x14
    int16_t  active_particle_count;   // 0x1C
    uint16_t flags;                   // 0x1E
    int16_t  frame_counter;           // 0x20
    /* Common fields (same in generic, P1, and P2): */
    uint8_t  callback_state[4];       // 0x22: Callback slot state (0=inactive, 1=active, 3=ending)
    uint8_t  effect_target_index;     // 0x26: Current target index
    uint8_t  unknown_27;              // 0x27: Unknown
    /* Pattern 1 specific fields: */
    int16_t  timeline_frame_counter;  // 0x28: Current frame in timeline
    int16_t  child_spawn_delay;       // 0x2A
    int16_t  spawned_target_count;    // 0x2C
    int16_t  phase1_particle_keyframe[5]; // 0x2E
    int16_t  phase2_particle_keyframe[5]; // 0x38
    int16_t  phase1_palette_keyframe;     // 0x42
    int16_t  phase2_palette_keyframe;     // 0x44
    int16_t  phase1_caster_keyframe;      // 0x46
    int16_t  phase2_caster_keyframe;      // 0x48
    int16_t  phase1_target_keyframe;      // 0x4A
    int16_t  phase2_target_keyframe;      // 0x4C
    int16_t  phase1_screen_keyframe;      // 0x4E
    int16_t  phase2_screen_keyframe;      // 0x50
    int16_t  phase1_track4_keyframe;      // 0x52
    int16_t  phase2_track4_keyframe;      // 0x54
    int16_t  phase1_track5_keyframe;      // 0x56
    int16_t  phase2_track5_keyframe;      // 0x58
    int16_t  phase1_track6_keyframe;      // 0x5A
    int16_t  phase2_track6_keyframe;      // 0x5C
    int16_t  phase2_track7_keyframe;      // 0x5E
    int16_t  gap_60;                  // 0x60
    int16_t  phase1_particle_duration[5]; // 0x62
    int16_t  phase2_particle_duration[5]; // 0x6C
    int16_t  phase1_palette_duration;     // 0x76
    int16_t  phase2_palette_duration;     // 0x78
    int16_t  phase1_caster_duration;      // 0x7A
    int16_t  phase2_caster_duration;      // 0x7C
    int16_t  phase1_target_duration;      // 0x7E
    int16_t  phase2_target_duration;      // 0x80
    int16_t  phase1_screen_duration;      // 0x82
    int16_t  phase2_screen_duration;      // 0x84
    int16_t  phase1_track4_duration;      // 0x86
    int16_t  phase2_track4_duration;      // 0x88
    int16_t  phase1_track5_duration;      // 0x8A
    int16_t  phase2_track5_duration;      // 0x8C
    int16_t  phase1_track6_duration;      // 0x8E
    int16_t  phase2_track6_duration;      // 0x90
    int16_t  phase2_track7_duration;      // 0x92
    int16_t  gap_94;                      // 0x94: Padding before spawn counters
    int16_t  phase1_particle_spawn[5];    // 0x96: Particle spawn counters (verified: 0x26+0x70=0x96)
    int16_t  phase2_particle_spawn[5];    // 0xA0: Particle spawn counters (verified: 0x26+0x7A=0xA0)
    uint8_t  gap_AA[17];                  // 0xAA-0xBA: Unknown/reserved
    /*
     * Dead code region (0xBB-0xC6) - 12 bytes
     *
     * Addresses in this region are passed as the 4th parameter to advance_p1_sound_track()
     * but the function IGNORES the 4th parameter entirely - verified via
     * disassembly at 0x801a478c (a3 is never read). These were likely planned
     * as per-track sound state values but the feature was never implemented.
     *
     * Verified from disassembly (s0 = effect_state + 0x26):
     *   Phase 1: s0+0x95=0xBB, s0+0x99=0xBF, s0+0x9D=0xC3
     *   Phase 2: s0+0x97=0xBD, s0+0x9B=0xC1, s0+0x9F=0xC5
     *
     * NOTE: These are at ODD byte offsets. Using int16_t would cause alignment
     * padding issues in Ghidra/compilers, so we use a byte array instead.
     */
    uint8_t  dead_code_BB[12];            // 0xBB-0xC6: DEAD CODE (addresses passed but ignored)
    uint8_t  gap_C7[9];                   // 0xC7-0xCF: Unknown/reserved
    /* End timeline fields */
    struct Particle *particle_list_head; // 0xD0
    void    *callback_ptrs[4];        // 0xD4
    void    *sprite_ptrs[4];          // 0xE4
    void    *current_callback_ptr;    // 0xF4
};

/* EffectState_P2 - For Pattern 2 functions (op_animate_tick) */
struct EffectState_P2 {
    int16_t  next_effect_index;       // 0x00
    int16_t  effect_index;            // 0x02
    int16_t  parent_effect_index;     // 0x04
    int16_t  script_position;         // 0x06
    int32_t *script_data_ptr;         // 0x08
    int16_t  child_effect_indices[4]; // 0x0C
    int16_t  script_regs[4];          // 0x14
    int16_t  active_particle_count;   // 0x1C
    uint16_t flags;                   // 0x1E
    int16_t  frame_counter;           // 0x20
    /* Common fields (same in generic, P1, and P2): */
    uint8_t  callback_state[4];       // 0x22: Callback slot state (0=inactive, 1=active, 3=ending)
    uint8_t  effect_target_index;     // 0x26: Current target index
    uint8_t  unknown_27;              // 0x27: Unknown
    int16_t  anim_progress;           // 0x28: Animation progress counter
    int16_t  particle_keyframe[5];    // 0x2A
    int16_t  sound_keyframe[3];       // 0x34
    int16_t  color_keyframe[4];       // 0x3A: Color track keyframes
    int16_t  gap_42;                  // 0x42
    int16_t  particle_duration[5];    // 0x44
    int16_t  sound_duration[3];       // 0x4E
    int16_t  color_duration[4];       // 0x54: Color track durations
    int16_t  gap_5C;                  // 0x5C
    int16_t  particle_spawn_counter[5]; // 0x5E
    uint8_t  extended_state[104];     // 0x68-0xCF
    /* End timeline fields */
    struct Particle *particle_list_head; // 0xD0
    void    *callback_ptrs[4];        // 0xD4
    void    *sprite_ptrs[4];          // 0xE4
    void    *current_callback_ptr;    // 0xF4
};

/* ParticleSystemHeader - 20 bytes */
struct ParticleSystemHeader {
    int32_t unknown_00;               // 0x00
    int32_t gravity_x;                // 0x04
    int32_t gravity_y;                // 0x08
    int32_t gravity_z;                // 0x0C
    int32_t inertia_threshold;        // 0x10
};

/* ParticleEmitter - 196 bytes (0xC4) */
struct ParticleEmitter {
    uint8_t  byte_00;                 // 0x00: unused
    uint8_t  anim_index;              // 0x01
    uint8_t  motion_type_flag;        // 0x02
    uint8_t  animation_target_flag;   // 0x03
    uint8_t  anim_param;              // 0x04
    uint8_t  byte_05;                 // 0x05: unused
    uint8_t  emitter_flags_lo;        // 0x06
    uint8_t  emitter_flags_hi;        // 0x07
    uint8_t  curve_indices_08;        // 0x08
    uint8_t  curve_indices_09;        // 0x09
    uint8_t  curve_indices_0A;        // 0x0A
    uint8_t  curve_indices_0B;        // 0x0B
    uint8_t  curve_indices_0C;        // 0x0C
    uint8_t  curve_indices_0D;        // 0x0D
    uint8_t  curve_indices_0E;        // 0x0E
    uint8_t  curve_indices_0F;        // 0x0F
    uint8_t  color_curves_rg;         // 0x10
    uint8_t  color_curves_b;          // 0x11
    uint8_t  unknown_12;              // 0x12
    uint8_t  unknown_13;              // 0x13
    int16_t  start_position_x;        // 0x14
    int16_t  start_position_y;        // 0x16
    int16_t  start_position_z;        // 0x18
    int16_t  end_position_x;          // 0x1A
    int16_t  end_position_y;          // 0x1C
    int16_t  end_position_z;          // 0x1E
    uint16_t spread_x_start;          // 0x20
    uint16_t spread_y_start;          // 0x22
    uint16_t spread_z_start;          // 0x24
    uint16_t spread_x_end;            // 0x26
    uint16_t spread_y_end;            // 0x28
    uint16_t spread_z_end;            // 0x2A
    int16_t  velocity_base_angle_x_start;  // 0x2C
    int16_t  velocity_base_angle_y_start;  // 0x2E
    int16_t  velocity_base_angle_z_start;  // 0x30
    int16_t  velocity_base_angle_x_end;    // 0x32
    int16_t  velocity_base_angle_y_end;    // 0x34
    int16_t  velocity_base_angle_z_end;    // 0x36
    int16_t  velocity_direction_spread_x_start;  // 0x38
    int16_t  velocity_direction_spread_y_start;  // 0x3A
    int16_t  velocity_direction_spread_z_start;  // 0x3C
    int16_t  velocity_direction_spread_x_end;    // 0x3E
    int16_t  velocity_direction_spread_y_end;    // 0x40
    int16_t  velocity_direction_spread_z_end;    // 0x42
    int16_t  inertia_min_start;       // 0x44
    int16_t  inertia_max_start;       // 0x46
    int16_t  inertia_min_end;         // 0x48
    int16_t  inertia_max_end;         // 0x4A
    int16_t  callback_param_0;         // 0x4C: Callback parameter (particle system lerps but discards)
    int16_t  callback_param_1;         // 0x4E: Callback parameter (particle system lerps but discards)
    int16_t  callback_param_2;         // 0x50: Callback parameter (particle system lerps but discards)
    int16_t  callback_param_3;         // 0x52: Callback parameter (particle system lerps but discards)
    int16_t  weight_min_start;        // 0x54
    int16_t  weight_max_start;        // 0x56
    int16_t  weight_min_end;          // 0x58
    int16_t  weight_max_end;          // 0x5A
    uint16_t radial_velocity_min_start;    // 0x5C
    uint16_t radial_velocity_max_start;    // 0x5E
    uint16_t radial_velocity_min_end;      // 0x60
    uint16_t radial_velocity_max_end;      // 0x62
    int16_t  acceleration_x_min_start;     // 0x64
    int16_t  acceleration_x_max_start;     // 0x66
    int16_t  acceleration_y_min_start;     // 0x68
    int16_t  acceleration_y_max_start;     // 0x6A
    int16_t  acceleration_z_min_start;     // 0x6C
    int16_t  acceleration_z_max_start;     // 0x6E
    int16_t  acceleration_x_min_end;       // 0x70
    int16_t  acceleration_x_max_end;       // 0x72
    int16_t  acceleration_y_min_end;       // 0x74
    int16_t  acceleration_y_max_end;       // 0x76
    int16_t  acceleration_z_min_end;       // 0x78
    int16_t  acceleration_z_max_end;       // 0x7A
    int16_t  drag_x_min_start;        // 0x7C
    int16_t  drag_x_max_start;        // 0x7E
    int16_t  drag_y_min_start;        // 0x80
    int16_t  drag_y_max_start;        // 0x82
    int16_t  drag_z_min_start;        // 0x84
    int16_t  drag_z_max_start;        // 0x86
    int16_t  drag_x_min_end;          // 0x88
    int16_t  drag_x_max_end;          // 0x8A
    int16_t  drag_y_min_end;          // 0x8C
    int16_t  drag_y_max_end;          // 0x8E
    int16_t  drag_z_min_end;          // 0x90
    int16_t  drag_z_max_end;          // 0x92
    uint16_t lifetime_min_start;      // 0x94
    uint16_t lifetime_max_start;      // 0x96
    uint16_t lifetime_min_end;        // 0x98
    uint16_t lifetime_max_end;        // 0x9A
    int16_t  target_offset_x_start;   // 0x9C
    int16_t  target_offset_y_start;   // 0x9E
    int16_t  target_offset_z_start;   // 0xA0
    int16_t  target_offset_x_end;     // 0xA2
    int16_t  target_offset_y_end;     // 0xA4
    int16_t  target_offset_z_end;     // 0xA6
    int16_t  callback_param_4;         // 0xA8: Callback parameter (not read by particle system)
    int16_t  callback_param_5;         // 0xAA: Callback parameter (not read by particle system)
    int16_t  callback_param_6;         // 0xAC: Callback parameter (not read by particle system)
    int16_t  callback_param_7;         // 0xAE: Callback parameter (not read by particle system)
    uint16_t particle_count_start;    // 0xB0
    uint16_t particle_count_end;      // 0xB2
    uint16_t spawn_interval_start;    // 0xB4
    uint16_t spawn_interval_end;      // 0xB6
    uint16_t homing_strength_min_start;    // 0xB8
    uint16_t homing_strength_max_start;    // 0xBA
    uint16_t homing_strength_min_end;      // 0xBC
    uint16_t homing_strength_max_end;      // 0xBE
    uint8_t  child_emitter_on_death;  // 0xC0
    uint8_t  child_emitter_mid_life;  // 0xC1
    uint8_t  reserved_C2;             // 0xC2
    uint8_t  reserved_C3;             // 0xC3
};

/* ============================================================================
 * CAMERA SYSTEM - Global state, not per-effect
 * Data at header[0x1C], runtime at 0x801b8a60+
 * See: STRUCTURE_DEFINITIONS.md Section 11, CAMERA_SYSTEM.md
 * ============================================================================ */

/* CameraAngles - Track 1 data (6 bytes) */
struct CameraAngles {
    int16_t pitch;                    // 0x00
    int16_t yaw;                      // 0x02
    int16_t roll;                     // 0x04
};

/* CameraPosition - Track 2/3 data (16 bytes) */
struct CameraPosition {
    int32_t x;                        // 0x00
    int32_t y;                        // 0x04
    int32_t z;                        // 0x08
    int32_t w;                        // 0x0C: zoom (Track 3) or unused (Track 2)
};

/* CameraAngleSlots - Runtime state at 0x801b8a60 */
struct CameraAngleSlots {
    int32_t frames_total;             // 0x00 (0x801b8a60)
    int32_t frame_counter;            // 0x04 (0x801b8a64)
    int16_t slot0[4];                 // 0x08 (0x801b8a68): final angles + pad
    int16_t slot1[4];                 // 0x10 (0x801b8a70): Track 1 output + pad
    int16_t slot2[4];                 // 0x18 (0x801b8a78): workspace + pad
    int16_t slot3[4];                 // 0x20 (0x801b8a80): saved slot + pad
};

/* CameraPositionSlots - Runtime state at 0x801b8a88 */
struct CameraPositionSlots {
    int32_t frames_total_t2;          // 0x00 (0x801b8a88)
    int32_t frame_counter_t2;         // 0x04 (0x801b8a8c)
    int32_t final_position[4];        // 0x08 (0x801b8a90): X,Y,Z,zoom
    int32_t track2_output[4];         // 0x18 (0x801b8aa0)
    int32_t track3_output[4];         // 0x28 (0x801b8ab0)
    int32_t saved_slot[4];            // 0x38 (0x801b8ac0)
    int32_t frames_total_t3;          // 0x48 (0x801b8ad0)
    int32_t frame_counter_t3;         // 0x4C (0x801b8ad4)
};

