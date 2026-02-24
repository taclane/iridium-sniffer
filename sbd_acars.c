/*
 * SBD/ACARS reassembly from IDA messages
 *
 * Extracts SBD (Short Burst Data) packets from reassembled IDA payloads,
 * handles multi-packet SBD reassembly, and parses ACARS messages.
 *
 * When libacars-2 is available (HAVE_LIBACARS), decodes ARINC-622 application
 * payloads including ADS-C position reports, CPDLC datalink, and more.
 *
 * Protocol details derived from iridium-toolkit reassembler/sbd.py (muccc)
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sbd_acars.h"

#ifdef HAVE_LIBACARS
#include <libacars/libacars.h>
#include <libacars/acars.h>
#include <libacars/reassembly.h>
#include <libacars/vstring.h>
#include <libacars/version.h>
#endif

/* ---- Configuration ---- */

int acars_json = 0;
static const char *station = NULL;

/* ---- UDP JSON streaming ---- */

static int udp_fd = -1;
static struct sockaddr_in udp_addr;

/* JSON output buffer -- used to build JSON for dual stdout/UDP dispatch */
#define JSON_BUF_SIZE 8192
static char json_buf[JSON_BUF_SIZE];
static int json_pos = 0;

static void json_buf_reset(void) { json_pos = 0; json_buf[0] = '\0'; }

static void json_buf_append(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void json_buf_append(const char *fmt, ...)
{
    if (json_pos >= JSON_BUF_SIZE - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(json_buf + json_pos, JSON_BUF_SIZE - json_pos, fmt, ap);
    va_end(ap);
    if (n > 0) json_pos += n;
    if (json_pos >= JSON_BUF_SIZE) json_pos = JSON_BUF_SIZE - 1;
}

static void json_buf_emit(void)
{
    if (json_pos == 0) return;

    /* stdout (--acars-json) */
    if (acars_json) {
        fwrite(json_buf, 1, json_pos, stdout);
        putchar('\n');
        fflush(stdout);
    }

    /* UDP stream (--acars-udp) */
    if (udp_fd >= 0) {
        sendto(udp_fd, json_buf, json_pos, 0,
               (struct sockaddr *)&udp_addr, sizeof(udp_addr));
    }
}

/* ---- Stats counters ---- */

static int stat_ida_total = 0;      /* total IDA messages received */
static int stat_sbd_total = 0;      /* SBD packets identified */
static int stat_sbd_short = 0;      /* short/mboxcheck messages */
static int stat_sbd_single = 0;     /* single-packet messages */
static int stat_sbd_multi_ok = 0;   /* completed multi-packet messages */
static int stat_sbd_multi_frag = 0; /* multi-packet fragments processed */
static int stat_sbd_broken = 0;     /* orphan/expired fragments */
static int stat_acars_total = 0;    /* ACARS messages decoded */
static int stat_acars_errors = 0;   /* ACARS with CRC/parity errors */

/* ---- Timestamp handling ---- */

static struct timespec wall_t0;
static uint64_t first_ts_ns = 0;
static int ts_initialized = 0;

static void ts_ensure_init(uint64_t ts_ns)
{
    if (!ts_initialized) {
        clock_gettime(CLOCK_REALTIME, &wall_t0);
        first_ts_ns = ts_ns;
        ts_initialized = 1;
    }
}

static void format_timestamp(uint64_t ts_ns, char *buf, int bufsz)
{
    ts_ensure_init(ts_ns);
    double elapsed = (double)(ts_ns - first_ts_ns) / 1e9;
    time_t wall_sec = wall_t0.tv_sec + (time_t)elapsed;
    struct tm tm;
    gmtime_r(&wall_sec, &tm);
    strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static double ts_to_unix(uint64_t ts_ns)
{
    ts_ensure_init(ts_ns);
    return (double)wall_t0.tv_sec +
           (double)wall_t0.tv_nsec / 1e9 +
           (double)(ts_ns - first_ts_ns) / 1e9;
}

/* ---- CRC-16/Kermit (reflected, poly=0x8408, init=0) ---- */

static uint16_t crc16_table[256];
static int crc_initialized = 0;

static void crc16_init(void)
{
    for (int i = 0; i < 256; i++) {
        uint16_t crc = (uint16_t)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x8408;
            else
                crc >>= 1;
        }
        crc16_table[i] = crc;
    }
    crc_initialized = 1;
}

#ifndef HAVE_LIBACARS
static uint16_t crc16_kermit(const uint8_t *data, int len)
{
    uint16_t crc = 0;
    for (int i = 0; i < len; i++)
        crc = crc16_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc;
}
#endif

/* ---- SBD multi-packet reassembly ---- */

#define SBD_MAX_MULTI    8
#define SBD_MAX_DATA     1024
#define SBD_TIMEOUT_NS   5000000000ULL  /* 5 seconds */

typedef struct {
    int active;
    int msgno;          /* last received message number */
    int msgcnt;         /* total expected messages */
    int ul;             /* direction: 1=uplink, 0=downlink */
    uint64_t timestamp; /* timestamp of last fragment */
    double frequency;
    float magnitude;
    uint8_t data[SBD_MAX_DATA];
    int data_len;
} sbd_multi_t;

static sbd_multi_t sbd_multi[SBD_MAX_MULTI];

/* ---- JSON string escaping ---- */

static void json_escape(const char *in, int inlen, char *out, int outsz)
{
    int o = 0;
    for (int i = 0; i < inlen && o < outsz - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = '"';
        } else if (c == '\\') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = '\\';
        } else if (c == '\n') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 'n';
        } else if (c == '\r') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 'r';
        } else if (c == '\t') {
            if (o + 2 >= outsz) break;
            out[o++] = '\\'; out[o++] = 't';
        } else if (c < 0x20 || c == 0x7f) {
            if (o + 6 >= outsz) break;
            o += snprintf(out + o, outsz - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* ================================================================
 * libacars path -- full ARINC-622/ADS-C/CPDLC decoding
 * ================================================================ */

#ifdef HAVE_LIBACARS

static la_reasm_ctx *reasm_ctx = NULL;

static void acars_parse_libacars(const uint8_t *data, int len, int ul,
                                  uint64_t timestamp, double frequency,
                                  float magnitude)
{
    if (len == 0 || data[0] != 0x01)
        return;

    /* Strip SOH marker (0x01) -- libacars expects data after SOH */
    data++;
    len--;

    /* Strip Iridium-specific 0x03 header (8 bytes of unknown meaning) */
    const uint8_t *ir_hdr = NULL;
    int ir_hdr_len = 0;
    if (len > 0 && data[0] == 0x03 && len >= 8) {
        ir_hdr = data;
        ir_hdr_len = 8;
        data += 8;
        len -= 8;
    }

    if (len < 13)
        return;

    la_msg_dir dir = ul ? LA_MSG_DIR_AIR2GND : LA_MSG_DIR_GND2AIR;

    /* Convert timestamp to struct timeval for libacars reassembly */
    double unix_time = ts_to_unix(timestamp);
    struct timeval tv;
    tv.tv_sec = (time_t)unix_time;
    tv.tv_usec = (long)((unix_time - (double)tv.tv_sec) * 1000000.0);

    la_proto_node *tree = la_acars_parse_and_reassemble(
        data, len, dir, reasm_ctx, tv);
    if (!tree)
        return;

    /* Find the ACARS message node */
    la_proto_node *acars_node = la_proto_tree_find_acars(tree);
    if (!acars_node || !acars_node->data) {
        la_proto_tree_destroy(tree);
        return;
    }

    la_acars_msg *msg = (la_acars_msg *)acars_node->data;

    /* Skip in-progress reassembly (multi-block ACARS) */
    if (msg->reasm_status == LA_REASM_IN_PROGRESS) {
        la_proto_tree_destroy(tree);
        return;
    }

    stat_acars_total++;
    if (msg->err)
        stat_acars_errors++;

    if (acars_json || udp_fd >= 0) {
        if (msg->err) {
            la_proto_tree_destroy(tree);
            return;
        }

        char ts_buf[32];
        format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

        /* Registration: strip leading dots */
        const char *reg = msg->reg;
        while (*reg == '.') reg++;

        /* Label: replace DEL with 'd' for compatibility */
        char label[4] = {0};
        label[0] = msg->label[0];
        label[1] = msg->label[1];
        if (label[0] == '_' && label[1] == 0x7f)
            label[1] = 'd';

        /* Ack: replace NAK (0x15) with '!' */
        char ack_str[4] = {0};
        if (msg->ack == 0x15)
            ack_str[0] = '!';
        else if (msg->ack)
            ack_str[0] = msg->ack;

        /* Flight ID: trim trailing spaces */
        char flight[8] = {0};
        memcpy(flight, msg->flight_id, 6);
        for (int i = 5; i >= 0 && flight[i] == ' '; i--)
            flight[i] = '\0';

        /* Escape text */
        char esc_text[4096] = {0};
        if (msg->txt && msg->txt[0])
            json_escape(msg->txt, (int)strlen(msg->txt),
                        esc_text, sizeof(esc_text));

        /* Build airframes.io compatible JSON into buffer */
        json_buf_reset();
        json_buf_append("{\"app\":{\"name\":\"iridium-sniffer\",\"version\":\"1.0\"},"
               "\"source\":{\"transport\":\"iridium\","
               "\"protocol\":\"acars\",\"parser\":\"libacars\"");
        if (station)
            json_buf_append(",\"station_id\":\"%s\"", station);
        json_buf_append("},\"acars\":{\"timestamp\":\"%s\","
               "\"errors\":%d,"
               "\"link_direction\":\"%s\","
               "\"block_end\":%s,"
               "\"mode\":\"%c\","
               "\"tail\":\"%s\"",
               ts_buf,
               msg->err ? 1 : 0,
               ul ? "uplink" : "downlink",
               msg->final_block ? "true" : "false",
               msg->mode,
               reg);

        if (ack_str[0])
            json_buf_append(",\"ack\":\"%s\"", ack_str);
        json_buf_append(",\"label\":\"%s\",\"block_id\":\"%c\"",
               label, msg->block_id);

        if (msg->msg_num[0])
            json_buf_append(",\"message_number\":\"%s%c\"",
                   msg->msg_num, msg->msg_num_seq);
        if (flight[0])
            json_buf_append(",\"flight\":\"%s\"", flight);
        if (msg->sublabel[0])
            json_buf_append(",\"sublabel\":\"%s\"", msg->sublabel);
        if (msg->mfi[0])
            json_buf_append(",\"mfi\":\"%s\"", msg->mfi);
        if (esc_text[0])
            json_buf_append(",\"text\":\"%s\"", esc_text);

        json_buf_append("}");

        /* Include decoded application layer (ARINC-622, ADS-C, CPDLC) */
        if (acars_node->next) {
            la_vstring *app_json = la_proto_tree_format_json(
                NULL, acars_node->next);
            if (app_json && app_json->str && app_json->len > 2) {
                json_buf_append(",%.*s", (int)(app_json->len - 2),
                       app_json->str + 1);
            }
            if (app_json)
                la_vstring_destroy(app_json, true);
        }

        json_buf_append(",\"freq\":%.0f,\"level\":%.2f", frequency, magnitude);
        if (ir_hdr && ir_hdr_len > 0) {
            json_buf_append(",\"header\":\"");
            for (int i = 0; i < ir_hdr_len; i++)
                json_buf_append("%02x", ir_hdr[i]);
            json_buf_append("\"");
        }
        json_buf_append("}");
        json_buf_emit();
    }

    if (!acars_json) {
        /* Text mode: timestamp + direction header, then libacars text */
        char ts_buf[32];
        format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

        printf("ACARS: %s %s ", ts_buf, ul ? "UL" : "DL");
        if (ir_hdr && ir_hdr_len > 0) {
            printf("[hdr:%s] ", "iridium");
        }

        la_vstring *vstr = la_proto_tree_format_text(NULL, tree);
        if (vstr && vstr->str) {
            /* Print the full decoded output from libacars */
            printf("\n%s", vstr->str);
        }
        if (vstr)
            la_vstring_destroy(vstr, true);

        fflush(stdout);
    }

    la_proto_tree_destroy(tree);
}

#else /* !HAVE_LIBACARS */

/* ================================================================
 * Fallback path -- basic ACARS field extraction (no ARINC-622)
 * ================================================================ */

static void acars_output_json(const uint8_t *data, int len, int ul,
                               uint64_t timestamp, double frequency,
                               float magnitude, const uint8_t *hdr, int hdr_len)
{
    if (len < 13)
        return;

    char mode[4] = {0};
    mode[0] = (char)data[0];

    char reg[8] = {0};
    int reg_start = 1;
    while (reg_start < 8 && data[reg_start] == '.')
        reg_start++;
    int rlen = 8 - reg_start;
    if (rlen > 0)
        memcpy(reg, data + reg_start, rlen);
    reg[rlen] = '\0';

    char ack[4] = {0};
    if (data[8] == 0x15)
        ack[0] = '!';
    else
        ack[0] = (char)data[8];

    char label[4] = {0};
    label[0] = (char)data[9];
    label[1] = (char)data[10];
    if (data[9] == '_' && data[10] == 0x7f) {
        label[0] = '_'; label[1] = 'd';
    }

    char block_id[4] = {0};
    block_id[0] = (char)data[11];

    const uint8_t *rest = data + 12;
    int rest_len = len - 12;

    int cont = 0;
    if (rest_len > 0) {
        if (rest[rest_len - 1] == 0x03) {
            rest_len--;
        } else if (rest[rest_len - 1] == 0x17) {
            cont = 1;
            rest_len--;
        }
    }

    char seq[8] = {0};
    char flight[8] = {0};
    const uint8_t *txt = NULL;
    int txt_len = 0;

    if (rest_len > 0 && rest[0] == 0x02) {
        if (ul) {
            if (rest_len >= 11) {
                memcpy(seq, rest + 1, 4); seq[4] = '\0';
                memcpy(flight, rest + 5, 6); flight[6] = '\0';
                txt = rest + 11;
                txt_len = rest_len - 11;
            } else {
                txt = rest + 1;
                txt_len = rest_len - 1;
            }
        } else {
            txt = rest + 1;
            txt_len = rest_len - 1;
        }
    }

    char ts_buf[32];
    format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

    char esc_reg[64], esc_mode[16], esc_label[16], esc_bid[16];
    char esc_ack[16], esc_seq[32], esc_flight[32], esc_text[2048];
    char esc_hdr[64];

    json_escape(mode, (int)strlen(mode), esc_mode, sizeof(esc_mode));
    json_escape(reg, (int)strlen(reg), esc_reg, sizeof(esc_reg));
    json_escape(ack, (int)strlen(ack), esc_ack, sizeof(esc_ack));
    json_escape(label, (int)strlen(label), esc_label, sizeof(esc_label));
    json_escape(block_id, (int)strlen(block_id), esc_bid, sizeof(esc_bid));
    json_escape(seq, (int)strlen(seq), esc_seq, sizeof(esc_seq));
    json_escape(flight, (int)strlen(flight), esc_flight, sizeof(esc_flight));
    if (txt && txt_len > 0)
        json_escape((const char *)txt, txt_len, esc_text, sizeof(esc_text));
    else
        esc_text[0] = '\0';

    esc_hdr[0] = '\0';
    if (hdr && hdr_len > 0) {
        int pos = 0;
        for (int i = 0; i < hdr_len && pos < (int)sizeof(esc_hdr) - 3; i++)
            pos += snprintf(esc_hdr + pos, sizeof(esc_hdr) - pos,
                            "%02x", hdr[i]);
    }

    json_buf_reset();
    json_buf_append("{\"app\":{\"name\":\"iridium-sniffer\",\"version\":\"1.0\"},"
           "\"source\":{\"transport\":\"iridium\",\"protocol\":\"acars\"");
    if (station)
        json_buf_append(",\"station_id\":\"%s\"", station);
    json_buf_append("},\"acars\":{\"timestamp\":\"%s\","
           "\"errors\":0,"
           "\"link_direction\":\"%s\","
           "\"block_end\":%s,"
           "\"mode\":\"%s\","
           "\"tail\":\"%s\"",
           ts_buf,
           ul ? "uplink" : "downlink",
           cont ? "false" : "true",
           esc_mode,
           esc_reg);
    if (ack[0])
        json_buf_append(",\"ack\":\"%s\"", esc_ack);
    json_buf_append(",\"label\":\"%s\",\"block_id\":\"%s\"",
           esc_label, esc_bid);
    if (ul && seq[0])
        json_buf_append(",\"message_number\":\"%s\"", esc_seq);
    if (ul && flight[0])
        json_buf_append(",\"flight\":\"%s\"", esc_flight);
    if (esc_text[0])
        json_buf_append(",\"text\":\"%s\"", esc_text);
    json_buf_append("},\"freq\":%.0f,\"level\":%.2f,\"header\":\"%s\"}",
           frequency, magnitude, esc_hdr);
    json_buf_emit();
}

static void acars_output_text(const uint8_t *data, int len, int ul,
                               uint64_t timestamp, double frequency,
                               float magnitude, const uint8_t *hdr, int hdr_len,
                               int errors)
{
    if (len < 13)
        return;

    char ts_buf[32];
    format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

    char mode = (char)data[0];

    char reg[8] = {0};
    int reg_start = 1;
    while (reg_start < 8 && data[reg_start] == '.')
        reg_start++;
    int rlen = 8 - reg_start;
    if (rlen > 0)
        memcpy(reg, data + reg_start, rlen);
    reg[rlen] = '\0';

    int is_nak = (data[8] == 0x15);
    char ack = (char)data[8];

    char label[4] = {0};
    if (data[9] == '_' && data[10] == 0x7f) {
        label[0] = '_'; label[1] = '?';
    } else {
        label[0] = (char)data[9];
        label[1] = (char)data[10];
    }

    char bid = (char)data[11];

    const uint8_t *rest = data + 12;
    int rest_len = len - 12;

    int cont = 0;
    if (rest_len > 0) {
        if (rest[rest_len - 1] == 0x03)
            rest_len--;
        else if (rest[rest_len - 1] == 0x17) {
            cont = 1;
            rest_len--;
        }
    }

    printf("ACARS: %s %s Mode:%c REG:%-7s ",
           ts_buf, ul ? "UL" : "DL", mode, reg);

    if (is_nak)
        printf("NAK  ");
    else
        printf("ACK:%c ", ack);

    printf("Label:%s bID:%c ", label, bid);

    if (rest_len > 0 && rest[0] == 0x02) {
        if (ul && rest_len >= 11) {
            printf("SEQ:%.4s FNO:%.6s ", rest + 1, rest + 5);
            if (rest_len > 11) {
                printf("[");
                for (int i = 11; i < rest_len; i++) {
                    char c = (char)rest[i];
                    if (c >= 0x20 && c < 0x7f)
                        putchar(c);
                    else
                        putchar('.');
                }
                printf("]");
            }
        } else {
            if (rest_len > 1) {
                printf("[");
                for (int i = 1; i < rest_len; i++) {
                    char c = (char)rest[i];
                    if (c >= 0x20 && c < 0x7f)
                        putchar(c);
                    else
                        putchar('.');
                }
                printf("]");
            }
        }
    }

    if (cont)
        printf(" CONT'd");

    if (errors > 0)
        printf(" ERRORS");

    printf("\n");
    fflush(stdout);
}

static void acars_parse_fallback(const uint8_t *data, int len, int ul,
                                  uint64_t timestamp, double frequency,
                                  float magnitude)
{
    if (len == 0 || data[0] != 0x01)
        return;

    if (len <= 2)
        return;

    data++;
    len--;

    uint8_t csum[2] = {0};
    int has_crc = 0;
    if (len >= 3 && data[len - 1] == 0x7f) {
        csum[0] = data[len - 3];
        csum[1] = data[len - 2];
        len -= 3;
        has_crc = 1;
    }

    const uint8_t *hdr = NULL;
    int hdr_len = 0;
    if (len > 0 && data[0] == 0x03) {
        if (len >= 8) {
            hdr = data;
            hdr_len = 8;
            data += 8;
            len -= 8;
        }
    }

    int crc_errors = 0;
    if (has_crc) {
        uint8_t crc_buf[SBD_MAX_DATA];
        int crc_len = len + 2;
        if (crc_len <= (int)sizeof(crc_buf)) {
            memcpy(crc_buf, data, len);
            crc_buf[len] = csum[0];
            crc_buf[len + 1] = csum[1];
            if (crc16_kermit(crc_buf, crc_len) != 0)
                crc_errors = 1;
        }
    } else {
        crc_errors = 1;
    }

    if (len < 13)
        return;

    uint8_t stripped[SBD_MAX_DATA];
    int parity_ok = 1;
    for (int i = 0; i < len; i++) {
        int bits = 0;
        uint8_t c = data[i];
        for (uint8_t b = c; b; b >>= 1)
            bits += b & 1;
        if ((bits % 2) == 0)
            parity_ok = 0;
        stripped[i] = c & 0x7F;
    }

    int errors = crc_errors + (!parity_ok);

    stat_acars_total++;
    if (errors > 0)
        stat_acars_errors++;

    if ((acars_json || udp_fd >= 0) && errors > 0)
        return;

    if (acars_json || udp_fd >= 0)
        acars_output_json(stripped, len, ul, timestamp, frequency, magnitude,
                          hdr, hdr_len);
    if (!acars_json)
        acars_output_text(stripped, len, ul, timestamp, frequency, magnitude,
                          hdr, hdr_len, errors);
}

#endif /* !HAVE_LIBACARS */

/* ---- SBD extraction ---- */

static void sbd_output_raw(const uint8_t *data, int len, int ul,
                            uint64_t timestamp, double frequency)
{
    if (acars_json)
        return;

    char ts_buf[32];
    format_timestamp(timestamp, ts_buf, sizeof(ts_buf));

    printf("SBD: %s %s ", ts_buf, ul ? "UL" : "DL");
    for (int i = 0; i < len && i < 64; i++)
        printf("%02x", data[i]);
    if (len > 64)
        printf("...");
    printf(" | ");
    for (int i = 0; i < len && i < 64; i++) {
        char c = (char)data[i];
        printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    printf("\n");
    fflush(stdout);
}

static void sbd_process(const uint8_t *sbd_data, int sbd_len, int ul,
                         uint64_t timestamp, double frequency,
                         float magnitude)
{
    /* Try ACARS first (marker byte 0x01) */
    if (sbd_len > 2 && sbd_data[0] == 0x01) {
#ifdef HAVE_LIBACARS
        acars_parse_libacars(sbd_data, sbd_len, ul, timestamp,
                             frequency, magnitude);
#else
        acars_parse_fallback(sbd_data, sbd_len, ul, timestamp,
                             frequency, magnitude);
#endif
        return;
    }

    /* Non-ACARS SBD: show raw in text mode */
    if (sbd_len > 0)
        sbd_output_raw(sbd_data, sbd_len, ul, timestamp, frequency);
}

static void sbd_expire(uint64_t now_ns)
{
    for (int i = 0; i < SBD_MAX_MULTI; i++) {
        if (sbd_multi[i].active &&
            now_ns > sbd_multi[i].timestamp + SBD_TIMEOUT_NS) {
            sbd_multi[i].active = 0;
        }
    }
}

static void sbd_extract(const uint8_t *data, int len, int ul,
                          uint64_t timestamp, double frequency,
                          float magnitude)
{
    if (len < 5)
        return;

    /* Check for SBD markers */
    int is_sbd = 0;
    if (data[0] == 0x76 && data[1] != 5) {
        if (ul) {
            if (data[1] >= 0x0c && data[1] <= 0x0e)
                is_sbd = 1;
        } else {
            if (data[1] >= 0x08 && data[1] <= 0x0b)
                is_sbd = 1;
        }
    } else if (data[0] == 0x06 && data[1] == 0x00) {
        if (data[2] == 0x00 || data[2] == 0x10 || data[2] == 0x20 ||
            data[2] == 0x40 || data[2] == 0x50 || data[2] == 0x70)
            is_sbd = 1;
    }

    if (!is_sbd)
        return;

    stat_sbd_total++;

    uint8_t typ0 = data[0];
    uint8_t typ1 = data[1];
    data += 2;
    len -= 2;

    int msgno = 0;
    int msgcnt = 0;
    const uint8_t *sbd_data = NULL;
    int sbd_len = 0;

    if (typ0 == 0x06 && typ1 == 0x00) {
        if (len < 30 || data[0] != 0x20)
            return;

        msgcnt = data[15];
        msgno = (msgcnt == 0) ? 0 : 1;
        sbd_data = data + 29;
        sbd_len = len - 29;
    } else {
        if (typ1 == 0x08) {
            if (len < 5)
                return;
            int prehdr_len;
            if (data[0] == 0x26)
                prehdr_len = 7;
            else if (data[0] == 0x20)
                prehdr_len = 5;
            else
                prehdr_len = 7;

            if (len < prehdr_len)
                return;

            msgcnt = data[3];
            data += prehdr_len;
            len -= prehdr_len;
        } else {
            msgcnt = -1;
        }

        if (ul && len >= 3 && (data[0] == 0x50 || data[0] == 0x51)) {
            data += 3;
            len -= 3;
        }

        if (len == 0) {
            msgno = 0;
            sbd_data = data;
            sbd_len = 0;
        } else if (len > 3 && data[0] == 0x10) {
            int pkt_len = data[1];
            msgno = data[2];
            data += 3;
            len -= 3;

            if (len < pkt_len)
                return;
            if (len > pkt_len)
                len = pkt_len;

            sbd_data = data;
            sbd_len = len;
        } else {
            msgno = 0;
            sbd_data = data;
            sbd_len = len;
        }
    }

    sbd_expire(timestamp);

    if (msgno == 0) {
        stat_sbd_short++;
        if (sbd_len > 0)
            sbd_process(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
    } else if (msgcnt == 1 && msgno == 1) {
        stat_sbd_single++;
        sbd_process(sbd_data, sbd_len, ul, timestamp, frequency, magnitude);
    } else if (msgcnt > 1) {
        int idx = -1;
        for (int i = 0; i < SBD_MAX_MULTI; i++) {
            if (!sbd_multi[i].active) { idx = i; break; }
        }
        if (idx < 0) {
            uint64_t oldest = UINT64_MAX;
            for (int i = 0; i < SBD_MAX_MULTI; i++) {
                if (sbd_multi[i].timestamp < oldest) {
                    oldest = sbd_multi[i].timestamp;
                    idx = i;
                }
            }
        }
        if (idx < 0) idx = 0;

        sbd_multi_t *s = &sbd_multi[idx];
        s->active = 1;
        s->msgno = msgno;
        s->msgcnt = msgcnt;
        s->ul = ul;
        s->timestamp = timestamp;
        s->frequency = frequency;
        s->magnitude = magnitude;
        s->data_len = (sbd_len > (int)sizeof(s->data)) ?
                      (int)sizeof(s->data) : sbd_len;
        memcpy(s->data, sbd_data, s->data_len);
    } else if (msgno > 1) {
        for (int i = SBD_MAX_MULTI - 1; i >= 0; i--) {
            sbd_multi_t *s = &sbd_multi[i];
            if (!s->active) continue;
            if (s->ul != ul) continue;
            if (msgno != s->msgno + 1) continue;

            int space = (int)sizeof(s->data) - s->data_len;
            int copy = (sbd_len > space) ? space : sbd_len;
            if (copy > 0) {
                memcpy(s->data + s->data_len, sbd_data, copy);
                s->data_len += copy;
            }
            s->msgno = msgno;
            s->timestamp = timestamp;

            stat_sbd_multi_frag++;
            if (msgno == s->msgcnt) {
                stat_sbd_multi_ok++;
                sbd_process(s->data, s->data_len, ul, timestamp,
                            s->frequency, s->magnitude);
                s->active = 0;
            }
            return;
        }
        stat_sbd_broken++;
    }
}

/* ---- Public API ---- */

void acars_init(const char *station_id, const char *udp_host, int udp_port)
{
    station = station_id;
    memset(sbd_multi, 0, sizeof(sbd_multi));
    if (!crc_initialized)
        crc16_init();

    /* UDP JSON streaming */
    if (udp_host) {
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) {
            perror("acars_init: UDP socket");
        } else {
            memset(&udp_addr, 0, sizeof(udp_addr));
            udp_addr.sin_family = AF_INET;
            udp_addr.sin_port = htons(udp_port);
            if (inet_pton(AF_INET, udp_host, &udp_addr.sin_addr) != 1) {
                fprintf(stderr, "acars_init: invalid UDP host '%s'\n",
                        udp_host);
                close(udp_fd);
                udp_fd = -1;
            } else {
                fprintf(stderr, "ACARS: UDP JSON stream -> %s:%d\n",
                        udp_host, udp_port);
            }
        }
    }

#ifdef HAVE_LIBACARS
    la_config_set_int("acars_bearer", LA_ACARS_BEARER_SATCOM);
    reasm_ctx = la_reasm_ctx_new();
    fprintf(stderr, "ACARS: libacars %s (ARINC-622/ADS-C/CPDLC decoding)\n",
            LA_VERSION);
#endif
}

void acars_shutdown(void)
{
    if (udp_fd >= 0) {
        close(udp_fd);
        udp_fd = -1;
    }
#ifdef HAVE_LIBACARS
    if (reasm_ctx) {
        la_reasm_ctx_destroy(reasm_ctx);
        reasm_ctx = NULL;
    }
    la_config_destroy();
#endif
}

void acars_ida_cb(const uint8_t *data, int len,
                  uint64_t timestamp, double frequency,
                  ir_direction_t direction, float magnitude,
                  void *user)
{
    (void)user;
    stat_ida_total++;
    int ul = (direction == DIR_UPLINK) ? 1 : 0;
    sbd_extract(data, len, ul, timestamp, frequency, magnitude);
}

void acars_print_stats(void)
{
    fprintf(stderr, "SBD: %d packets from %d IDA messages "
            "(%d short, %d single, %d multi-pkt)\n",
            stat_sbd_total, stat_ida_total,
            stat_sbd_short, stat_sbd_single, stat_sbd_multi_ok);
    if (stat_sbd_multi_frag > 0 || stat_sbd_broken > 0)
        fprintf(stderr, "SBD: %d multi-pkt fragments, %d broken/orphan\n",
                stat_sbd_multi_frag, stat_sbd_broken);
    fprintf(stderr, "ACARS: %d messages decoded", stat_acars_total);
    if (stat_acars_errors > 0)
        fprintf(stderr, " (%d with errors)", stat_acars_errors);
    fprintf(stderr, "\n");
}
