#include "pb.h"

int g_pb_overflow;

void pbo_varint(pb_out_t *o, uint64_t v) {
    uint8_t t[10]; int n = 0;
    do { uint8_t b = (uint8_t)(v & 0x7f); v >>= 7; if (v) b |= 0x80; t[n++] = b; } while (v && n < 10);
    pbo_raw(o, t, n);
}
void pbo_u64(pb_out_t *o, int field, uint64_t v) { pbo_tag(o, field, 0); pbo_varint(o, v); }
void pbo_i32(pb_out_t *o, int field, int32_t v) {
    pbo_tag(o, field, 5);
    uint8_t t[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    pbo_raw(o, t, 4);
}
void pbo_str(pb_out_t *o, int field, const char *s) { pbo_bytes(o, field, (const uint8_t *)s, (int)strlen(s)); }
void pbo_bytes(pb_out_t *o, int field, const uint8_t *b, int n) { pbo_tag(o, field, 2); pbo_varint(o, (uint64_t)n); pbo_raw(o, b, n); }
void pbo_msg(pb_out_t *o, int field, const pb_out_t *sub) { pbo_bytes(o, field, sub->buf, sub->len); }

void pbi_init(pb_it_t *it, const uint8_t *buf, int len) {
    memset(it, 0, sizeof(*it));
    it->buf = buf; it->len = len; it->pos = 0; it->wire = -1;
}
static bool rd_varint(pb_it_t *it, uint64_t *out) {
    uint64_t v = 0; int sh = 0;
    while (it->pos < it->len) {
        uint8_t b = it->buf[it->pos++];
        v |= (uint64_t)(b & 0x7f) << sh;
        if (!(b & 0x80)) { *out = v; return true; }
        sh += 7;
        if (sh > 63) return false;
    }
    return false;
}
bool pbi_next(pb_it_t *it) {
    if (it->pos >= it->len) return false;
    uint64_t tag;
    if (!rd_varint(it, &tag)) return false;
    it->field = (int)(tag >> 3);
    it->wire = (int)(tag & 7);
    it->body = NULL; it->body_len = 0; it->v = 0;
    switch (it->wire) {
    case 0: return rd_varint(it, &it->v);
    case 1: if (it->pos + 8 > it->len) return false; memcpy(&it->v, it->buf + it->pos, 8); it->pos += 8; return true;
    case 2: {
        uint64_t n;
        if (!rd_varint(it, &n) || it->pos + (int)n > it->len) return false;
        it->body = it->buf + it->pos; it->body_len = (int)n; it->pos += (int)n;
        return true;
    }
    case 5: if (it->pos + 4 > it->len) return false; { uint32_t u; memcpy(&u, it->buf + it->pos, 4); it->v = u; } it->pos += 4; return true;
    default: return false;
    }
}
uint64_t pb_get_u64(const uint8_t *buf, int len, int field, uint64_t dflt) {
    pb_it_t it; pbi_init(&it, buf, len);
    while (pbi_next(&it)) if (it.field == field && it.wire == 0) return it.v;
    return dflt;
}
const uint8_t *pb_get_bytes(const uint8_t *buf, int len, int field, int *out_len) {
    pb_it_t it; pbi_init(&it, buf, len);
    while (pbi_next(&it)) if (it.field == field && it.wire == 2) { if (out_len) *out_len = it.body_len; return it.body; }
    if (out_len) *out_len = 0;
    return NULL;
}
