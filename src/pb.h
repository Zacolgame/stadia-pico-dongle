// pb.h — tiny protobuf reader/writer (wire format only; schemas are known).
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct { uint8_t *buf; int len, cap; } pb_out_t;

static inline void pbo_init(pb_out_t *o, uint8_t *buf, int cap) { o->buf = buf; o->cap = cap; o->len = 0; }
extern int g_pb_overflow;   // incremented whenever a write is dropped
static inline void pbo_raw(pb_out_t *o, const uint8_t *b, int n) {
    if (o->len + n <= o->cap) { memcpy(o->buf + o->len, b, n); o->len += n; }
    else { g_pb_overflow++; }   // never silent: a dropped payload corrupts the message
}
void pbo_varint(pb_out_t *o, uint64_t v);
static inline void pbo_tag(pb_out_t *o, int field, int wire) { pbo_varint(o, ((uint64_t)field << 3) | wire); }
void pbo_u64(pb_out_t *o, int field, uint64_t v);           // varint field
void pbo_i32(pb_out_t *o, int field, int32_t v);            // fixed32 field
void pbo_str(pb_out_t *o, int field, const char *s);        // string field
void pbo_bytes(pb_out_t *o, int field, const uint8_t *b, int n);
void pbo_msg(pb_out_t *o, int field, const pb_out_t *sub);  // nested message

// reader
typedef struct {
    const uint8_t *buf; int len;
    int pos;                 // cursor: next unread byte
    int field, wire;         // current field after pbi_next()
    const uint8_t *body;     // wire==2 payload
    int body_len;
    uint64_t v;              // varint / fixed value
} pb_it_t;

void pbi_init(pb_it_t *it, const uint8_t *buf, int len);
bool pbi_next(pb_it_t *it);  // false when exhausted / malformed

// convenience: find first field N (int value) in a message body
uint64_t pb_get_u64(const uint8_t *buf, int len, int field, uint64_t dflt);
const uint8_t *pb_get_bytes(const uint8_t *buf, int len, int field, int *out_len);
