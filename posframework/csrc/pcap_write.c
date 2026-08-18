/**
 * pcap_write.c - Fast PCAP file writer for handshake capture
 *
 * Implements PCAP file creation and frame writing using standard
 * PCAP file format (libpcap-compatible). No external library dependency.
 *
 * Replaces Python struct.pack()-based PCAP writing in handshake.py
 * for significantly faster file I/O during capture.
 *
 * No external dependencies. Pure C11 with standard library only.
 *
 * Compile: gcc -std=c11 -shared -fPIC -o libpcap_write.so pcap_write.c
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include "pcap_write.h"

/* ==================== PCAP File Format Structures ==================== */

/**
 * PCAP Global Header (24 bytes).
 * Written once at the beginning of the file.
 */
struct pcap_global_header {
    uint32_t magic_number;   /* 0xA1B2C3D4 */
    uint16_t version_major;  /* 2 */
    uint16_t version_minor;  /* 4 */
    int32_t  thiszone;       /* GMT offset (usually 0) */
    uint32_t sigfigs;        /* Timestamp accuracy (usually 0) */
    uint32_t snaplen;        /* Max packet length captured */
    uint32_t network;        /* Link-layer type */
} __attribute__((packed));

/**
 * PCAP Packet Header (16 bytes).
 * Written before each packet/frame.
 */
struct pcap_packet_header {
    uint32_t ts_sec;         /* Timestamp seconds */
    uint32_t ts_usec;        /* Timestamp microseconds */
    uint32_t incl_len;       /* Number of bytes captured */
    uint32_t orig_len;       /* Original packet length */
} __attribute__((packed));

/**
 * PCAP writer internal state.
 */
struct pcap_writer {
    int       fd;            /* File descriptor */
    uint32_t  snaplen;       /* Maximum capture length */
    uint32_t  link_type;     /* Link layer type */
    uint32_t  frame_count;   /* Frames written */
    uint64_t  file_size;     /* Current file size */
};

/* ==================== Internal Helpers ==================== */

/**
 * Write the PCAP global header to a file descriptor.
 */
static int write_global_header(int fd, uint32_t link_type, uint32_t snaplen)
{
    struct pcap_global_header hdr;

    hdr.magic_number  = PCAP_MAGIC_NUMBER;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone      = 0;
    hdr.sigfigs       = 0;
    hdr.snaplen       = snaplen;
    hdr.network       = link_type;

    ssize_t ret = write(fd, &hdr, sizeof(hdr));
    if (ret != (ssize_t)sizeof(hdr)) {
        return -1;
    }

    return 0;
}

/**
 * Write a single packet to a file descriptor.
 */
static int write_packet(int fd, const uint8_t *data, size_t len,
                        uint32_t ts_sec, uint32_t ts_usec, uint32_t snaplen)
{
    struct pcap_packet_header pkt_hdr;
    size_t cap_len = len;

    if (cap_len > snaplen) {
        cap_len = snaplen;
    }

    pkt_hdr.ts_sec   = ts_sec;
    pkt_hdr.ts_usec  = ts_usec;
    pkt_hdr.incl_len = (uint32_t)cap_len;
    pkt_hdr.orig_len = (uint32_t)len;

    /* Write packet header */
    ssize_t ret = write(fd, &pkt_hdr, sizeof(pkt_hdr));
    if (ret != (ssize_t)sizeof(pkt_hdr)) {
        return -1;
    }

    /* Write packet data */
    ret = write(fd, data, cap_len);
    if (ret != (ssize_t)cap_len) {
        return -1;
    }

    return 0;
}

/* ==================== Public API ==================== */

__attribute__((visibility("default")))
pcap_writer_t *pcap_writer_open(const char *filename, uint32_t link_type, uint32_t snaplen)
{
    pcap_writer_t *writer;
    int fd;

    if (!filename) {
        errno = EINVAL;
        return NULL;
    }

    if (snaplen == 0) {
        snaplen = PCAP_MAX_SNAPLEN;
    }

    /* Open file for writing (create/truncate) */
    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return NULL;
    }

    /* Write global header */
    if (write_global_header(fd, link_type, snaplen) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return NULL;
    }

    /* Allocate writer struct */
    writer = (pcap_writer_t *)calloc(1, sizeof(pcap_writer_t));
    if (!writer) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }

    writer->fd          = fd;
    writer->snaplen     = snaplen;
    writer->link_type   = link_type;
    writer->frame_count = 0;
    writer->file_size   = sizeof(struct pcap_global_header);

    return writer;
}

__attribute__((visibility("default")))
int pcap_writer_write_frame(pcap_writer_t *writer,
                            const uint8_t *data, size_t len,
                            uint32_t ts_sec, uint32_t ts_usec)
{
    if (!writer || !data || len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (write_packet(writer->fd, data, len, ts_sec, ts_usec, writer->snaplen) < 0) {
        return -1;
    }

    size_t cap_len = len > writer->snaplen ? writer->snaplen : len;
    writer->frame_count++;
    writer->file_size += sizeof(struct pcap_packet_header) + cap_len;

    return 0;
}

__attribute__((visibility("default")))
int pcap_writer_write_batch(pcap_writer_t *writer,
                            const uint8_t **frames, const size_t *lens,
                            const uint32_t *ts_secs, const uint32_t *ts_usecs,
                            int count)
{
    int written = 0;

    if (!writer || !frames || !lens || !ts_secs || !ts_usecs || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    for (int i = 0; i < count; i++) {
        if (!frames[i] || lens[i] == 0) {
            continue;
        }

        if (pcap_writer_write_frame(writer, frames[i], lens[i],
                                     ts_secs[i], ts_usecs[i]) < 0) {
            return written > 0 ? written : -1;
        }
        written++;
    }

    return written;
}

__attribute__((visibility("default")))
void pcap_writer_close(pcap_writer_t *writer)
{
    if (!writer) {
        return;
    }

    if (writer->fd >= 0) {
        fsync(writer->fd);
        close(writer->fd);
    }

    free(writer);
}

__attribute__((visibility("default")))
uint32_t pcap_writer_frame_count(const pcap_writer_t *writer)
{
    if (!writer) {
        return 0;
    }
    return writer->frame_count;
}

__attribute__((visibility("default")))
uint64_t pcap_writer_file_size(const pcap_writer_t *writer)
{
    if (!writer) {
        return 0;
    }
    return writer->file_size;
}

__attribute__((visibility("default")))
int pcap_write_file(const char *filename, uint32_t link_type,
                    const uint8_t **frames, const size_t *lens,
                    const uint32_t *ts_secs, const uint32_t *ts_usecs,
                    int count)
{
    pcap_writer_t *writer;

    if (!filename || !frames || !lens || !ts_secs || !ts_usecs || count <= 0) {
        errno = EINVAL;
        return -1;
    }

    writer = pcap_writer_open(filename, link_type, PCAP_MAX_SNAPLEN);
    if (!writer) {
        return -1;
    }

    int result = pcap_writer_write_batch(writer, frames, lens, ts_secs, ts_usecs, count);

    pcap_writer_close(writer);

    return result >= 0 ? 0 : -1;
}
