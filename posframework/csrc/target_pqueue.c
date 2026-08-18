/**
 * target_pqueue.c - Native priority queue for target scoring and selection
 *
 * Implements a binary max-heap for efficient target prioritization.
 * Provides O(log n) insert, O(1) peek, and O(n log n) batch sort
 * for WiFi target selection during autonomous attack operations.
 *
 * Used by target_queue.py and target_scorer.py.
 *
 * No external dependencies. Pure C11 with standard library only.
 *
 * Compile: gcc -std=c11 -shared -fPIC -o libtarget_pqueue.so target_pqueue.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "target_pqueue.h"

/* ==================== Internal Heap Implementation ==================== */

/**
 * Priority queue (binary max-heap).
 */
struct pqueue {
    pqueue_target_t heap[PQUEUE_MAX_TARGETS];
    int size;
};

/**
 * Swap two targets in the heap.
 */
static void heap_swap(pqueue_target_t *a, pqueue_target_t *b)
{
    pqueue_target_t temp = *a;
    *a = *b;
    *b = temp;
}

/**
 * Bubble up element at index i to maintain heap property.
 */
static void heap_bubble_up(pqueue_t *pq, int i)
{
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (pq->heap[i].priority > pq->heap[parent].priority) {
            heap_swap(&pq->heap[i], &pq->heap[parent]);
            i = parent;
        } else {
            break;
        }
    }
}

/**
 * Bubble down element at index i to maintain heap property.
 */
static void heap_bubble_down(pqueue_t *pq, int i)
{
    int size = pq->size;

    while (1) {
        int largest = i;
        int left = 2 * i + 1;
        int right = 2 * i + 2;

        if (left < size && pq->heap[left].priority > pq->heap[largest].priority) {
            largest = left;
        }
        if (right < size && pq->heap[right].priority > pq->heap[largest].priority) {
            largest = right;
        }

        if (largest != i) {
            heap_swap(&pq->heap[i], &pq->heap[largest]);
            i = largest;
        } else {
            break;
        }
    }
}

/* ==================== Priority Calculation ==================== */

/**
 * Internal priority calculation.
 */
static double calculate_priority(int rssi, int is_pos, int is_enterprise,
                                 int client_count, int vector_count)
{
    double score = 0.0;

    /* POS targets get highest priority */
    if (is_pos) {
        score += 150.0;
    }

    /* Signal strength factor (RSSI -100 to 0, mapped to 0-50) */
    int clamped_rssi = rssi;
    if (clamped_rssi < -100) clamped_rssi = -100;
    if (clamped_rssi > 0) clamped_rssi = 0;
    score += (double)(clamped_rssi + 100) * 0.5;

    /* Client count bonus (more clients = more interesting, cap at 30) */
    int client_bonus = client_count * 5;
    if (client_bonus > 30) client_bonus = 30;
    score += (double)client_bonus;

    /* Attack vector count bonus */
    score += (double)vector_count * 3.0;

    /* Enterprise targets get bonus (high-value) */
    if (is_enterprise) {
        score += 25.0;
    }

    return score;
}

/* ==================== Comparison for qsort ==================== */

static int compare_targets_desc(const void *a, const void *b)
{
    const pqueue_target_t *ta = (const pqueue_target_t *)a;
    const pqueue_target_t *tb = (const pqueue_target_t *)b;

    if (ta->priority > tb->priority) return -1;
    if (ta->priority < tb->priority) return 1;
    return 0;
}

/* ==================== Public API ==================== */

__attribute__((visibility("default")))
pqueue_t *pqueue_create(void)
{
    pqueue_t *pq = (pqueue_t *)calloc(1, sizeof(pqueue_t));
    if (!pq) {
        errno = ENOMEM;
        return NULL;
    }
    pq->size = 0;
    return pq;
}

__attribute__((visibility("default")))
void pqueue_destroy(pqueue_t *pq)
{
    if (pq) {
        free(pq);
    }
}

__attribute__((visibility("default")))
void pqueue_clear(pqueue_t *pq)
{
    if (pq) {
        pq->size = 0;
    }
}

__attribute__((visibility("default")))
double pqueue_calculate_priority(int rssi, int is_pos, int is_enterprise,
                                 int client_count, int vector_count)
{
    return calculate_priority(rssi, is_pos, is_enterprise, client_count, vector_count);
}

__attribute__((visibility("default")))
int pqueue_insert(pqueue_t *pq, const char *bssid, const char *ssid,
                  int rssi, int client_count, int vector_count,
                  int is_pos, int is_enterprise, int channel)
{
    if (!pq || !bssid) {
        errno = EINVAL;
        return -1;
    }

    if (pq->size >= PQUEUE_MAX_TARGETS) {
        errno = ENOSPC;
        return -1;
    }

    pqueue_target_t *target = &pq->heap[pq->size];
    memset(target, 0, sizeof(pqueue_target_t));

    strncpy(target->bssid, bssid, BSSID_LEN - 1);
    target->bssid[BSSID_LEN - 1] = '\0';

    if (ssid) {
        strncpy(target->ssid, ssid, SSID_LEN - 1);
        target->ssid[SSID_LEN - 1] = '\0';
    }

    target->rssi = rssi;
    target->client_count = client_count;
    target->vector_count = vector_count;
    target->is_pos = is_pos;
    target->is_enterprise = is_enterprise;
    target->channel = channel;
    target->cooldown_until = 0;

    /* Calculate priority */
    target->priority = calculate_priority(rssi, is_pos, is_enterprise,
                                          client_count, vector_count);

    /* Bubble up to maintain heap property */
    pq->size++;
    heap_bubble_up(pq, pq->size - 1);

    return 0;
}

__attribute__((visibility("default")))
int pqueue_peek(const pqueue_t *pq, pqueue_target_t *out)
{
    if (!pq || !out) {
        errno = EINVAL;
        return -1;
    }

    if (pq->size == 0) {
        errno = ENODATA;
        return -1;
    }

    *out = pq->heap[0];
    return 0;
}

__attribute__((visibility("default")))
int pqueue_pop(pqueue_t *pq, pqueue_target_t *out)
{
    if (!pq || !out) {
        errno = EINVAL;
        return -1;
    }

    if (pq->size == 0) {
        errno = ENODATA;
        return -1;
    }

    /* Copy top element */
    *out = pq->heap[0];

    /* Move last element to top and bubble down */
    pq->size--;
    if (pq->size > 0) {
        pq->heap[0] = pq->heap[pq->size];
        heap_bubble_down(pq, 0);
    }

    return 0;
}

__attribute__((visibility("default")))
int pqueue_size(const pqueue_t *pq)
{
    if (!pq) return 0;
    return pq->size;
}

__attribute__((visibility("default")))
int pqueue_batch_sort(pqueue_target_t *targets, int count)
{
    if (!targets || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Calculate priority for each target */
    for (int i = 0; i < count; i++) {
        targets[i].priority = calculate_priority(
            targets[i].rssi, targets[i].is_pos, targets[i].is_enterprise,
            targets[i].client_count, targets[i].vector_count
        );
    }

    /* Sort by priority descending */
    qsort(targets, (size_t)count, sizeof(pqueue_target_t), compare_targets_desc);

    return 0;
}

__attribute__((visibility("default")))
int pqueue_set_cooldown(pqueue_t *pq, const char *bssid, uint32_t cooldown_sec)
{
    if (!pq || !bssid) {
        errno = EINVAL;
        return -1;
    }

    uint32_t cooldown_until = (uint32_t)time(NULL) + cooldown_sec;

    /* Search for target in heap */
    for (int i = 0; i < pq->size; i++) {
        if (strncmp(pq->heap[i].bssid, bssid, BSSID_LEN) == 0) {
            pq->heap[i].cooldown_until = cooldown_until;
            return 0;
        }
    }

    errno = ENOENT;
    return -1;
}

__attribute__((visibility("default")))
int pqueue_get_sorted(const pqueue_t *pq, pqueue_target_t *out, int max_out)
{
    if (!pq || !out || max_out <= 0) {
        errno = EINVAL;
        return -1;
    }

    int count = pq->size < max_out ? pq->size : max_out;

    /* Copy heap to output array */
    memcpy(out, pq->heap, (size_t)count * sizeof(pqueue_target_t));

    /* Sort by priority descending */
    qsort(out, (size_t)count, sizeof(pqueue_target_t), compare_targets_desc);

    return count;
}
