/**
 * state_machine.c - Native state machine engine for AutoPwn orchestration
 *
 * Implements a validated state machine with:
 * - Legal transition enforcement
 * - Concurrent attack target tracking (up to 8 simultaneous)
 * - Session timing and duration limits
 * - Battery safety threshold checks
 * - State transition history
 * - Per-state time accumulation statistics
 *
 * Used by autopwn_engine.py for high-performance state management.
 *
 * No external dependencies. Pure C11 with standard library only.
 *
 * Compile: gcc -std=c11 -shared -fPIC -o libstate_machine.so state_machine.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "state_machine.h"

/* ==================== Transition Table ==================== */

/**
 * Valid state transitions matrix.
 * transition_valid[from][to] = 1 means transition is allowed.
 *
 * Valid transitions:
 *   IDLE     -> SCANNING, STOPPING
 *   SCANNING -> ANALYZING, PAUSED, STOPPING
 *   ANALYZING -> ATTACKING, SCANNING, PAUSED, STOPPING
 *   ATTACKING -> CRACKING, ANALYZING, SCANNING, PAUSED, STOPPING
 *   CRACKING  -> SCANNING, ANALYZING, PAUSED, STOPPING
 *   PAUSED    -> SCANNING, ANALYZING, ATTACKING, IDLE, STOPPING
 *   STOPPING  -> IDLE
 */
static const int transition_valid[SM_STATE_COUNT][SM_STATE_COUNT] = {
    /* To:   IDLE SCAN ANAL ATTK CRCK PAUS STOP */
    /* IDLE     */ { 0,   1,   0,   0,   0,   0,   1 },
    /* SCANNING */ { 0,   0,   1,   0,   0,   1,   1 },
    /* ANALYZING*/ { 0,   1,   0,   1,   0,   1,   1 },
    /* ATTACKING*/ { 0,   1,   1,   0,   1,   1,   1 },
    /* CRACKING */ { 0,   1,   1,   0,   0,   1,   1 },
    /* PAUSED   */ { 1,   1,   1,   1,   0,   0,   1 },
    /* STOPPING */ { 1,   0,   0,   0,   0,   0,   0 },
};

/* State name strings */
static const char *state_names[SM_STATE_COUNT] = {
    "IDLE",
    "SCANNING",
    "ANALYZING",
    "ATTACKING",
    "CRACKING",
    "PAUSED",
    "STOPPING",
};

/* ==================== Internal Structure ==================== */

struct state_machine {
    /* Current state */
    int current_state;

    /* Configuration */
    int max_concurrent;
    uint64_t max_duration_ms;
    int battery_threshold;

    /* Attack tracking */
    sm_attack_slot_t attacks[SM_MAX_CONCURRENT];
    int attack_count;

    /* Timing */
    uint64_t session_start_ms;
    uint64_t last_transition_ms;

    /* Statistics */
    sm_stats_t stats;

    /* State transition history (ring buffer) */
    sm_history_entry_t history[SM_HISTORY_SIZE];
    int history_head;
    int history_count;
};

/* ==================== Internal Helpers ==================== */

/**
 * Get current time in milliseconds (monotonic).
 */
static uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/**
 * Record a state transition in history.
 */
static void record_transition(state_machine_t *sm, int from, int to, uint64_t ts)
{
    int idx = sm->history_head;
    sm->history[idx].from_state = from;
    sm->history[idx].to_state = to;
    sm->history[idx].timestamp = ts;

    sm->history_head = (sm->history_head + 1) % SM_HISTORY_SIZE;
    if (sm->history_count < SM_HISTORY_SIZE) {
        sm->history_count++;
    }
}

/**
 * Accumulate time spent in a state.
 */
static void accumulate_state_time(state_machine_t *sm, int state, uint64_t duration_ms)
{
    switch (state) {
    case SM_STATE_SCANNING:
        sm->stats.total_scan_time += duration_ms;
        break;
    case SM_STATE_ATTACKING:
        sm->stats.total_attack_time += duration_ms;
        break;
    case SM_STATE_CRACKING:
        sm->stats.total_crack_time += duration_ms;
        break;
    default:
        break;
    }
}

/* ==================== Public API ==================== */

__attribute__((visibility("default")))
state_machine_t *sm_create(int max_concurrent, uint64_t max_duration_ms,
                           int battery_threshold)
{
    state_machine_t *sm;

    if (max_concurrent < 1) max_concurrent = 1;
    if (max_concurrent > SM_MAX_CONCURRENT) max_concurrent = SM_MAX_CONCURRENT;
    if (battery_threshold < 0) battery_threshold = 0;
    if (battery_threshold > 100) battery_threshold = 100;

    sm = (state_machine_t *)calloc(1, sizeof(state_machine_t));
    if (!sm) {
        errno = ENOMEM;
        return NULL;
    }

    sm->current_state = SM_STATE_IDLE;
    sm->max_concurrent = max_concurrent;
    sm->max_duration_ms = max_duration_ms;
    sm->battery_threshold = battery_threshold;
    sm->attack_count = 0;
    sm->session_start_ms = get_time_ms();
    sm->last_transition_ms = sm->session_start_ms;
    sm->stats.session_start = sm->session_start_ms;
    sm->history_head = 0;
    sm->history_count = 0;

    memset(sm->attacks, 0, sizeof(sm->attacks));

    return sm;
}

__attribute__((visibility("default")))
void sm_destroy(state_machine_t *sm)
{
    if (sm) {
        free(sm);
    }
}

__attribute__((visibility("default")))
int sm_get_state(const state_machine_t *sm)
{
    if (!sm) return SM_STATE_IDLE;
    return sm->current_state;
}

__attribute__((visibility("default")))
int sm_can_transition(const state_machine_t *sm, int to_state)
{
    if (!sm) return 0;
    if (to_state < 0 || to_state >= SM_STATE_COUNT) return 0;
    return transition_valid[sm->current_state][to_state];
}

__attribute__((visibility("default")))
int sm_transition(state_machine_t *sm, int to_state)
{
    if (!sm) {
        errno = EINVAL;
        return -1;
    }

    if (to_state < 0 || to_state >= SM_STATE_COUNT) {
        errno = EINVAL;
        return -1;
    }

    if (!transition_valid[sm->current_state][to_state]) {
        errno = EPERM;
        return -1;
    }

    uint64_t now = get_time_ms();
    uint64_t duration = now - sm->last_transition_ms;

    /* Accumulate time in previous state */
    accumulate_state_time(sm, sm->current_state, duration);

    /* Record transition */
    record_transition(sm, sm->current_state, to_state, now);

    /* Track scan completions */
    if (sm->current_state == SM_STATE_SCANNING && to_state != SM_STATE_SCANNING) {
        sm->stats.scans_completed++;
    }

    /* Update state */
    int from_state = sm->current_state;
    sm->current_state = to_state;
    sm->last_transition_ms = now;
    sm->stats.transition_count++;

    /* Clear attack slots on transition to IDLE or STOPPING */
    if (to_state == SM_STATE_IDLE || to_state == SM_STATE_STOPPING) {
        sm->attack_count = 0;
        memset(sm->attacks, 0, sizeof(sm->attacks));
    }

    (void)from_state; /* Suppress unused warning */
    return 0;
}

__attribute__((visibility("default")))
int sm_register_attack(state_machine_t *sm, const char *bssid,
                       int channel, uint64_t timeout_ms)
{
    if (!sm || !bssid) {
        errno = EINVAL;
        return -1;
    }

    if (sm->attack_count >= sm->max_concurrent) {
        errno = ENOSPC;
        return -1;
    }

    /* Find an empty slot */
    int slot = -1;
    for (int i = 0; i < sm->max_concurrent; i++) {
        if (sm->attacks[i].status == SM_ATTACK_PENDING &&
            sm->attacks[i].bssid[0] == '\0') {
            slot = i;
            break;
        }
    }

    /* Also check for completed/failed slots that can be reused */
    if (slot < 0) {
        for (int i = 0; i < sm->max_concurrent; i++) {
            if (sm->attacks[i].status == SM_ATTACK_SUCCESS ||
                sm->attacks[i].status == SM_ATTACK_FAILED ||
                sm->attacks[i].status == SM_ATTACK_TIMEOUT) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0) {
        errno = ENOSPC;
        return -1;
    }

    /* Fill the slot */
    memset(&sm->attacks[slot], 0, sizeof(sm_attack_slot_t));
    strncpy(sm->attacks[slot].bssid, bssid, SM_BSSID_LEN - 1);
    sm->attacks[slot].bssid[SM_BSSID_LEN - 1] = '\0';
    sm->attacks[slot].status = SM_ATTACK_ACTIVE;
    sm->attacks[slot].start_time = get_time_ms();
    sm->attacks[slot].timeout_ms = timeout_ms;
    sm->attacks[slot].channel = channel;
    sm->attacks[slot].retry_count = 0;

    sm->attack_count++;
    sm->stats.targets_attacked++;

    return slot;
}

__attribute__((visibility("default")))
int sm_update_attack(state_machine_t *sm, int slot, int status)
{
    if (!sm || slot < 0 || slot >= SM_MAX_CONCURRENT) {
        errno = EINVAL;
        return -1;
    }

    int old_status = sm->attacks[slot].status;
    sm->attacks[slot].status = status;

    /* Track completions */
    if (old_status == SM_ATTACK_ACTIVE) {
        if (status == SM_ATTACK_SUCCESS) {
            sm->stats.targets_cracked++;
            sm->attack_count--;
        } else if (status == SM_ATTACK_FAILED || status == SM_ATTACK_TIMEOUT) {
            sm->stats.targets_failed++;
            sm->attack_count--;
        }
    }

    /* Ensure attack_count doesn't go negative */
    if (sm->attack_count < 0) sm->attack_count = 0;

    return 0;
}

__attribute__((visibility("default")))
int sm_active_attacks(const state_machine_t *sm)
{
    if (!sm) return 0;

    int count = 0;
    for (int i = 0; i < sm->max_concurrent; i++) {
        if (sm->attacks[i].status == SM_ATTACK_ACTIVE) {
            count++;
        }
    }
    return count;
}

__attribute__((visibility("default")))
int sm_check_timeouts(state_machine_t *sm, uint64_t current_ms)
{
    if (!sm) return 0;

    int timed_out = 0;
    for (int i = 0; i < sm->max_concurrent; i++) {
        if (sm->attacks[i].status == SM_ATTACK_ACTIVE) {
            uint64_t elapsed = current_ms - sm->attacks[i].start_time;
            if (sm->attacks[i].timeout_ms > 0 && elapsed >= sm->attacks[i].timeout_ms) {
                sm->attacks[i].status = SM_ATTACK_TIMEOUT;
                sm->stats.targets_failed++;
                sm->attack_count--;
                if (sm->attack_count < 0) sm->attack_count = 0;
                timed_out++;
            }
        }
    }
    return timed_out;
}

__attribute__((visibility("default")))
int sm_check_duration(const state_machine_t *sm, uint64_t current_ms)
{
    if (!sm) return 0;
    if (sm->max_duration_ms == 0) return 0; /* Unlimited */

    uint64_t elapsed = current_ms - sm->session_start_ms;
    return elapsed >= sm->max_duration_ms ? 1 : 0;
}

__attribute__((visibility("default")))
int sm_check_battery(const state_machine_t *sm, int battery_percent)
{
    if (!sm) return 0;
    if (sm->battery_threshold == 0) return 0; /* Disabled */
    return battery_percent <= sm->battery_threshold ? 1 : 0;
}

__attribute__((visibility("default")))
int sm_get_stats(const state_machine_t *sm, sm_stats_t *out)
{
    if (!sm || !out) {
        errno = EINVAL;
        return -1;
    }

    *out = sm->stats;

    /* Add current state time up to now */
    uint64_t now = get_time_ms();
    uint64_t current_duration = now - sm->last_transition_ms;

    switch (sm->current_state) {
    case SM_STATE_SCANNING:
        out->total_scan_time += current_duration;
        break;
    case SM_STATE_ATTACKING:
        out->total_attack_time += current_duration;
        break;
    case SM_STATE_CRACKING:
        out->total_crack_time += current_duration;
        break;
    default:
        break;
    }

    return 0;
}

__attribute__((visibility("default")))
const char *sm_state_name(int state)
{
    if (state < 0 || state >= SM_STATE_COUNT) {
        return "UNKNOWN";
    }
    return state_names[state];
}

__attribute__((visibility("default")))
void sm_reset(state_machine_t *sm)
{
    if (!sm) return;

    sm->current_state = SM_STATE_IDLE;
    sm->attack_count = 0;
    sm->session_start_ms = get_time_ms();
    sm->last_transition_ms = sm->session_start_ms;
    sm->history_head = 0;
    sm->history_count = 0;

    memset(sm->attacks, 0, sizeof(sm->attacks));
    memset(&sm->stats, 0, sizeof(sm_stats_t));
    sm->stats.session_start = sm->session_start_ms;
}
