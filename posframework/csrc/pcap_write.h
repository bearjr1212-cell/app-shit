/**
 * pcap_write.h - Fast PCAP file writer for handshake capture
 *
 * Provides efficient PCAP file creation and frame writing without
 * depending on libpcap. Used by handshake.py for writing captured
 * EAPOL frames to standard PCAP format files.
 *
 * Supports both classic PCAP and minimal format compatible with
 * hashcat, aircrack-ng, and Wireshark.
 */

#ifndef PCAP_WRITE_H
#define PCAP_WRITE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PCAP link layer types */
#define PCAP_LINKTYPE_ETHERNET     1
#define PCAP_LINKTYPE_IEEE802_11   105
#define PCAP_LINKTYPE_RADIOTAP     127

/* PCAP magic number */
#define PCAP_MAGIC_NUMBER  0xA1B2C3D4

/* Maximum single frame size */
#define PCAP_MAX_SNAPLEN   65535

/**
 * Opaque PCAP writer handle.
 */
typedef struct pcap_writer pcap_writer_t;

/**
 * Create a new PCAP file with standard global header.
 *
 * @param filename      Path to the output file
 * @param link_type     Link layer type (PCAP_LINKTYPE_*)
 * @param snaplen       Maximum capture length (default: 65535)
 * @return              Writer handle on success, NULL on error (errno set)
 */
__attribute__((visibility("default")))
pcap_writer_t *pcap_writer_open(const char *filename, uint32_t link_type, uint32_t snaplen);

/**
 * Write a single packet/frame to the PCAP file.
 *
 * @param writer        Writer handle from pcap_writer_open()
 * @param data          Frame data
 * @param len           Length of frame data
 * @param ts_sec        Timestamp seconds (Unix epoch)
 * @param ts_usec       Timestamp microseconds
 * @return              0 on success, -1 on error
 */
__attribute__((visibility("default")))
int pcap_writer_write_frame(pcap_writer_t *writer,
                            const uint8_t *data, size_t len,
                            uint32_t ts_sec, uint32_t ts_usec);

/**
 * Write multiple frames to the PCAP file in a batch.
 *
 * @param writer        Writer handle
 * @param frames        Array of frame data pointers
 * @param lens          Array of frame lengths
 * @param ts_secs       Array of timestamp seconds
 * @param ts_usecs      Array of timestamp microseconds
 * @param count         Number of frames to write
 * @return              Number of frames written, -1 on fatal error
 */
__attribute__((visibility("default")))
int pcap_writer_write_batch(pcap_writer_t *writer,
                            const uint8_t **frames, const size_t *lens,
                            const uint32_t *ts_secs, const uint32_t *ts_usecs,
                            int count);

/**
 * Flush and close the PCAP file.
 *
 * @param writer        Writer handle (freed after this call)
 */
__attribute__((visibility("default")))
void pcap_writer_close(pcap_writer_t *writer);

/**
 * Get the number of frames written so far.
 *
 * @param writer        Writer handle
 * @return              Number of frames written
 */
__attribute__((visibility("default")))
uint32_t pcap_writer_frame_count(const pcap_writer_t *writer);

/**
 * Get the current file size in bytes.
 *
 * @param writer        Writer handle
 * @return              File size in bytes
 */
__attribute__((visibility("default")))
uint64_t pcap_writer_file_size(const pcap_writer_t *writer);

/**
 * Write a PCAP file in one shot (header + all frames).
 *
 * Convenience function for writing a complete PCAP file at once.
 * Useful for exporting handshake captures.
 *
 * @param filename      Path to output file
 * @param link_type     Link layer type (PCAP_LINKTYPE_*)
 * @param frames        Array of frame data pointers
 * @param lens          Array of frame lengths
 * @param ts_secs       Array of timestamp seconds
 * @param ts_usecs      Array of timestamp microseconds
 * @param count         Number of frames
 * @return              0 on success, -1 on error
 */
__attribute__((visibility("default")))
int pcap_write_file(const char *filename, uint32_t link_type,
                    const uint8_t **frames, const size_t *lens,
                    const uint32_t *ts_secs, const uint32_t *ts_usecs,
                    int count);

#ifdef __cplusplus
}
#endif

#endif /* PCAP_WRITE_H */
