/*
 * Frame output in iridium-toolkit RAW format
 *
 * Format:
 *   RAW: {file_info} {timestamp_ms:012.4f} {freq_hz:010d} N:{mag:05.2f}{noise:+06.2f}
 *        I:{id:011d} {conf:3d}% {level:.5f} {payload_symbols:3d} {bits...}
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "frame_output.h"
#include "iridium.h"

static const char *out_file_info = NULL;
static uint64_t t0 = 0;
static int initialized = 0;

void frame_output_init(const char *fi)
{
    out_file_info = fi;
}

void frame_output_print(demod_frame_t *frame)
{
    /* Auto-initialize t0 from first frame timestamp */
    if (!initialized) {
        t0 = (frame->timestamp / 1000000000ULL) * 1000000000ULL;

        /* Auto-generate file_info if not provided */
        if (out_file_info == NULL || out_file_info[0] == '\0') {
            static char auto_info[64];
            snprintf(auto_info, sizeof(auto_info),
                     "i-%" PRIu64 "-t1", (uint64_t)(t0 / 1000000000ULL));
            out_file_info = auto_info;
        }
        initialized = 1;
    }

    /* Relative timestamp in milliseconds */
    double ts_ms = (double)(frame->timestamp - t0) / 1000000.0;

    /* Center frequency rounded to nearest Hz */
    int freq_hz = (int)(frame->center_frequency + 0.5);

    /* Payload symbols (after unique word) */
    int payload_syms = frame->n_payload_symbols;
    if (payload_syms < 0) payload_syms = 0;

    /* Print header fields */
    printf("RAW: %s %012.4f %010d N:%05.2f%+06.2f I:%011" PRIu64
           " %3d%% %.5f %3d ",
           out_file_info,
           ts_ms,
           freq_hz,
           frame->magnitude,
           frame->noise,
           frame->id,
           frame->confidence,
           frame->level,
           payload_syms);

    /* Print bits */
    for (int i = 0; i < frame->n_bits; i++)
        putchar('0' + frame->bits[i]);

    putchar('\n');
    fflush(stdout);
}
