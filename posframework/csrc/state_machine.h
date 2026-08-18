/**
 * state_machine.h - Native state machine engine for AutoPwn orchestration
 *
 * Provides a high-performance state machine with validated transitions,
 * concurrent target tracking, session timing, and battery safety checks.
 * Used by autopwn_engine.py for fast state transition validation and
 * multi-target coordination.
 *
 * States: IDLE, SCANNING, ANALYZING, ATTACKING, CRACKING, PAUSED, STOPPING
 */

#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* State machine states */
#define SM_STATE_IDLE       0
#define SM_STATE_SCANNING   1
#define SM_STATE_ANALYZING  2
#define SM_STATE_ATTACKING  3
#define SM_STATE_CRACKING   4
#define SM_STATE_PAUSED     5
#define SM_STATE_STOPPING   6
#define SM_STATE_COUNT      7

/* Maximum concurrent attack targets */
#define SM_MAX_CONCURRENT   8

/* Maximum state history entries */
#define SM_HISTORY_SIZE     64

/* BSSID string length */
#define SM_BSSID_LEN        18

/* Attack status for tracked targets */
#define SM_ATTACK_PENDING   0
#define SM_ATTACK_ACTIVE    1
#define SM_ATTACK_SUCCESS   2
#define SM_ATTACK_FAILED    3
#define SM_ATTACK_TIMEOUT   4

/**
 * Active attack target slot.
 */
typedef struct {
    char     bssid[SM_BSSID_LEN];   /* Target BSSID */
    int      status;                 /* SM_ATTACK_* status */
    uint64_t start_time;             /* Attack start timestamp (ms) */
    uint64_t timeout_ms;             /* Timeout duration (ms) */
    int      channel;                /* Target channel */
    int      retry_count;            /* Number of retries */
} sm_attack_slot_t;

/**
 * State transition history entry.
 */
typedef struct {
    int      from_state;             /* Previous state */
    int      to_state;               /* New state */
    uint64_t timestamp;              /* Transition timestamp (ms) */
} sm_history_entry_t;

/**
 * State machine statistics.
 */
typedef struct {
    uint64_t session_start;          /* Session start timestamp (ms) */
    uint64_t total_scan_time;        /* Total time in SCANNING (ms) */
    uint64_t total_attack_time;      /* Total time in ATTACKING (ms) */
    uint64_t total_crack_time;       /* Total time in CRACKING (ms) */
    int      transition_count;       /* Total state transitions */
    int      targets_attacked;       /* Total targets attacked */
    int      targets_cracked;        /* Total targets cracked */
    int      targets_failed;         /* Total targets failed */
    int      scans_completed;        /* Total scan cycles */
} sm_stats_t;

/**
 * State machine handle (opaque).
 */
typedef struct state_machine state_machine_t;

/**
 * Create a new state machine instance.
 *
 * @param max_concurrent   Maximum concurrent attacks (1-8)
 * @param max_duration_ms  Maximum session duration in ms (0 = unlimited)
 * @param battery_threshold  Battery % to stop at (0 = disabled)
 * @return                 State machine handle, NULL on error
 */
__attribute__((visibility("default")))
state_machine_t *sm_create(int max_concurrent, uint64_t max_duration_ms,
                           int battery_threshold);

/**
 * Destroy a state machine and free resources.
 *
 * @param sm   State machine handle
 */
__attribute__((visibility("default")))
void sm_destroy(state_machine_t *sm);

/**
 * Get the current state.
 *
 * @param sm   State machine handle
 * @return     Current state (SM_STATE_*)
 */
__attribute__((visibility("default")))
int sm_get_state(const state_machine_t *sm);

/**
 * Check if a state transition is valid.
 *
 * @param sm         State machine handle
 * @param to_state   Desired target state
 * @return           1 if valid, 0 if invalid
 */
__attribute__((visibility("default")))
int sm_can_transition(const state_machine_t *sm, int to_state);

/**
 * Attempt a state transition.
 *
 * @param sm         State machine handle
 * @param to_state   Desired target state
 * @return           0 on success, -1 if transition invalid
 */
__attribute__((visibility("default")))
int sm_transition(state_machine_t *sm, int to_state);

/**
 * Register an attack target in a concurrent slot.
 *
 * @param sm         State machine handle
 * @param bssid      Target BSSID
 * @param channel    Target channel
 * @param timeout_ms Attack timeout in milliseconds
 * @return           Slot index (0-based) on success, -1 if full
 */
__attribute__((visibility("default")))
int sm_register_attack(state_machine_t *sm, const char *bssid,
                       int channel, uint64_t timeout_ms);

/**
 * Update the status of an attack slot.
 *
 * @param sm         State machine handle
 * @param slot       Slot index
 * @param status     New status (SM_ATTACK_*)
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int sm_update_attack(state_machine_t *sm, int slot, int status);

/**
 * Get the number of active attack slots.
 *
 * @param sm   State machine handle
 * @return     Number of active attacks
 */
__attribute__((visibility("default")))
int sm_active_attacks(const state_machine_t *sm);

/**
 * Check for timed-out attacks and mark them.
 *
 * @param sm           State machine handle
 * @param current_ms   Current timestamp in milliseconds
 * @return             Number of attacks that timed out
 */
__attribute__((visibility("default")))
int sm_check_timeouts(state_machine_t *sm, uint64_t current_ms);

/**
 * Check if session duration limit has been reached.
 *
 * @param sm           State machine handle
 * @param current_ms   Current timestamp in milliseconds
 * @return             1 if duration exceeded, 0 otherwise
 */
__attribute__((visibility("default")))
int sm_check_duration(const state_machine_t *sm, uint64_t current_ms);

/**
 * Check if battery level is below threshold.
 *
 * @param sm               State machine handle
 * @param battery_percent  Current battery percentage (0-100)
 * @return                 1 if below threshold, 0 otherwise
 */
__attribute__((visibility("default")))
int sm_check_battery(const state_machine_t *sm, int battery_percent);

/**
 * Get statistics for the current session.
 *
 * @param sm    State machine handle
 * @param out   Output stats structure
 * @return      0 on success
 */
__attribute__((visibility("default")))
int sm_get_stats(const state_machine_t *sm, sm_stats_t *out);

/**
 * Get the state name as a string.
 *
 * @param state   State value (SM_STATE_*)
 * @return        Static string name (do not free)
 */
__attribute__((visibility("default")))
const char *sm_state_name(int state);

/**
 * Reset the state machine to IDLE.
 *
 * Clears all attack slots and resets statistics.
 *
 * @param sm   State machine handle
 */
__attribute__((visibility("default")))
void sm_reset(state_machine_t *sm);

#ifdef __cplusplus
}
#endif

#endif /* STATE_MACHINE_H */
