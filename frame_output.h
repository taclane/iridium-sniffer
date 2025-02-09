/*
 * Frame output in iridium-toolkit RAW format
 */

#ifndef __FRAME_OUTPUT_H__
#define __FRAME_OUTPUT_H__

#include "qpsk_demod.h"

/* Initialize frame output. file_info is borrowed, must remain valid.
 * If NULL, auto-generates from first timestamp. */
void frame_output_init(const char *file_info);

/* Print one demodulated frame in iridium-toolkit RAW format to stdout. */
void frame_output_print(demod_frame_t *frame);

#endif
