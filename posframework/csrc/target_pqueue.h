/**
 * target_pqueue.h - Native priority queue for target scoring and selection
 *
 * Provides high-performance target priority scoring and sorted queue
 * operations. Used by target_queue.py and target_scorer.py for fast
 * re-prioritization of WiFi targets during scanning.
 *
 * Implements a binary max-heap for O(log n) insert and O(1) top-target
 * access, with batch scoring for efficient bulk operations.
 */

#ifndef TARGET_PQUEUE_H
#define TARGET_PQUEUE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum targets in the priority queue */
#define PQUEUE_MAX_TARGETS 512

/* Maximum BSSID string length (17 chars + null) */
#define BSSID_LEN 18

/* Maximum SSID length (32 chars + null) */
#define SSID_LEN 33

/**
 * Target entry in the priority queue.
 */
typedef struct {
    char     bssid[BSSID_LEN];     /* BSSID string "AA:BB:CC:DD:EE:FF" */
    char     ssid[SSID_LEN];       /* SSID string */
    int      rssi;                 /* Signal strength (-100 to 0) */
    int      client_count;         /* Number of associated clients */
    int      vector_count;         /* Number of applicable attack vectors */
    int      is_pos;               /* 1 if POS target, 0 otherwise */
    int      is_enterprise;        /* 1 if enterprise target */
    int      channel;              /* WiFi channel */
    uint32_t cooldown_until;       /* Cooldown timestamp (0 = no cooldown) */
    double   priority;             /* Calculated priority score */
} pqueue_target_t;

/**
 * Priority queue handle (opaque).
 */
typedef struct pqueue pqueue_t;

/**
 * Create a new priority queue.
 *
 * @return   Queue handle, NULL on allocation failure
 */
__attribute__((visibility("default")))
pqueue_t *pqueue_create(void);

/**
 * Destroy a priority queue and free memory.
 *
 * @param pq   Queue handle
 */
__attribute__((visibility("default")))
void pqueue_destroy(pqueue_t *pq);

/**
 * Clear all targets from the queue.
 *
 * @param pq   Queue handle
 */
__attribute__((visibility("default")))
void pqueue_clear(pqueue_t *pq);

/**
 * Calculate priority score for a target based on its attributes.
 *
 * Scoring factors:
 *   - POS vendor match: +100
 *   - POS SSID match: +80
 *   - Signal strength: 0-50 (based on RSSI)
 *   - Client count: up to +30
 *   - Vector count: +3 per vector
 *   - Target type bonus: varies
 *
 * @param rssi           Signal strength (-100 to 0)
 * @param is_pos         1 if POS target
 * @param is_enterprise  1 if enterprise target
 * @param client_count   Number of associated clients
 * @param vector_count   Number of attack vectors
 * @return               Priority score (higher = more interesting)
 */
__attribute__((visibility("default")))
double pqueue_calculate_priority(int rssi, int is_pos, int is_enterprise,
                                 int client_count, int vector_count);

/**
 * Insert a target into the priority queue.
 * Automatically calculates priority based on attributes.
 *
 * @param pq             Queue handle
 * @param bssid          BSSID string
 * @param ssid           SSID string
 * @param rssi           Signal strength
 * @param client_count   Number of clients
 * @param vector_count   Number of attack vectors
 * @param is_pos         1 if POS target
 * @param is_enterprise  1 if enterprise target
 * @param channel        WiFi channel
 * @return               0 on success, -1 if queue full
 */
__attribute__((visibility("default")))
int pqueue_insert(pqueue_t *pq, const char *bssid, const char *ssid,
                  int rssi, int client_count, int vector_count,
                  int is_pos, int is_enterprise, int channel);

/**
 * Get the highest-priority target (peek, does not remove).
 *
 * @param pq     Queue handle
 * @param out    Output target data
 * @return       0 on success, -1 if queue empty
 */
__attribute__((visibility("default")))
int pqueue_peek(const pqueue_t *pq, pqueue_target_t *out);

/**
 * Remove and return the highest-priority target.
 *
 * @param pq     Queue handle
 * @param out    Output target data
 * @return       0 on success, -1 if queue empty
 */
__attribute__((visibility("default")))
int pqueue_pop(pqueue_t *pq, pqueue_target_t *out);

/**
 * Get the number of targets in the queue.
 *
 * @param pq     Queue handle
 * @return       Target count
 */
__attribute__((visibility("default")))
int pqueue_size(const pqueue_t *pq);

/**
 * Batch score and sort an array of targets by priority (descending).
 *
 * Calculates priority for each target and sorts them in-place.
 * Faster than individual inserts for bulk operations.
 *
 * @param targets    Array of target structs (modified in-place)
 * @param count      Number of targets
 * @return           0 on success, -1 on error
 */
__attribute__((visibility("default")))
int pqueue_batch_sort(pqueue_target_t *targets, int count);

/**
 * Apply cooldown to a target by BSSID.
 *
 * Sets a timestamp before which the target should not be re-attacked.
 *
 * @param pq             Queue handle
 * @param bssid          BSSID to cooldown
 * @param cooldown_sec   Cooldown duration in seconds
 * @return               0 on success, -1 if target not found
 */
__attribute__((visibility("default")))
int pqueue_set_cooldown(pqueue_t *pq, const char *bssid, uint32_t cooldown_sec);

/**
 * Get all targets sorted by priority (export to flat array).
 *
 * @param pq       Queue handle
 * @param out      Output array (caller allocates, size >= pqueue_size)
 * @param max_out  Maximum entries to write
 * @return         Number of targets written
 */
__attribute__((visibility("default")))
int pqueue_get_sorted(const pqueue_t *pq, pqueue_target_t *out, int max_out);

#ifdef __cplusplus
}
#endif

#endif /* TARGET_PQUEUE_H */
