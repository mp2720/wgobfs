#include "packet.h"

#include "utils.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WO_PACKET_FILLER_MAX_SIZE 24

struct woObfuscator {
    size_t buf_size;
    unsigned char *packet_buf;

    struct {
        unsigned short values[8192];
        size_t cur_idx;
    } pregen_rnd;
};

woError wo_obfuscator_init(struct woObfuscator **out_pb, size_t payload_mtu) {
    assert(payload_mtu <= WO_PACKET_PAYLOAD_MAX_SIZE);

    struct woObfuscator *const pb = WO_MALLOC(sizeof **out_pb);
    if (pb == NULL) {
        return WO_ERR(WO_ERR_MALLOC, 0);
    }

    pb->buf_size = WO_PACKET_HEADER_SIZE + payload_mtu;
    pb->packet_buf = WO_MALLOC(pb->buf_size);
    if (pb->packet_buf == NULL) {
        free(*out_pb);
        return WO_ERR(WO_ERR_MALLOC, 0);
    }

    unsigned int seed = time(NULL) % UINT_MAX;
    pb->pregen_rnd.cur_idx = 0;
    for (size_t i = 0; i < WO_ARR_LEN(pb->pregen_rnd.values); ++i) {
        pb->pregen_rnd.values[i] = rand_r(&seed);
    }

    *out_pb = pb;

    return WO_OK;
}

void wo_obfuscator_free(struct woObfuscator *pb) {
    free(pb->packet_buf);
    free(pb);
}

struct woBuffer wo_obfuscator_get_payload_buf(struct woObfuscator *obfs) {
    return (struct woBuffer){.ptr = obfs->packet_buf + WO_PACKET_HEADER_SIZE,
                             .capacity = obfs->buf_size - WO_PACKET_HEADER_SIZE};
}

struct woBuffer wo_obfuscator_get_packet_buf(struct woObfuscator *obfs) {
    return (struct woBuffer){.ptr = obfs->packet_buf, .capacity = obfs->buf_size};
}

static unsigned long long min_uint(unsigned long long a, unsigned long long b) {
    return a < b ? a : b;
}

static unsigned short next_rand(struct woObfuscator *pb) {
    const unsigned short v = pb->pregen_rnd.values[pb->pregen_rnd.cur_idx];

    pb->pregen_rnd.cur_idx += 1;
    pb->pregen_rnd.cur_idx %= WO_ARR_LEN(pb->pregen_rnd.values);

    return v;
}

// WARNING: generates randoms with slight bias
static unsigned short next_rand_n(struct woObfuscator *rnd, unsigned short upper_bound) {
    uint_fast32_t v = next_rand(rnd);
    v *= upper_bound;
    v >>= 16;
    return v;
}

static void xor_buf(unsigned char *buf, size_t start, size_t size, const woKey key) {
    for (size_t i = start; i < start + size; ++i) {
        buf[i] ^= key[i % sizeof(woKey)];
    }
}

size_t
wo_obfuscate(struct woObfuscator *obfs, const woKey key, const struct woPacketHeader *header) {
    assert(header->payload_size + WO_PACKET_HEADER_SIZE <= obfs->buf_size);

    size_t offset = 0;

    // write header
    {
        // payload size
        obfs->packet_buf[offset++] = (header->payload_size & 0xFF00) >> 8;
        obfs->packet_buf[offset++] = header->payload_size & 0x00FF;

        // address
        memcpy(obfs->packet_buf + offset, header->addr_port.addr, sizeof header->addr_port.addr);
        offset += sizeof header->addr_port.addr;

        // port
        obfs->packet_buf[offset++] = (header->addr_port.port & 0xFF00) >> 8;
        obfs->packet_buf[offset++] = header->addr_port.port & 0x00FF;
    }

    offset += header->payload_size;

    // write filler
    {
        const size_t filler_max_size_for_packet = min_uint(
            obfs->buf_size - WO_PACKET_HEADER_SIZE - header->payload_size,
            min_uint(header->payload_size, WO_PACKET_FILLER_MAX_SIZE)
        );

        const size_t filler_size = next_rand_n(obfs, filler_max_size_for_packet + 1);

        // offset of the payload data that will be used as filler
        const size_t payload_filler_offset = next_rand_n(obfs, header->payload_size - filler_size);

        memcpy(
            obfs->packet_buf + offset,
            obfs->packet_buf + WO_PACKET_HEADER_SIZE + payload_filler_offset,
            filler_size
        );
        offset += filler_size;
    }

    xor_buf(obfs->packet_buf, 0, offset, key);

    return (ssize_t)offset;
}

bool wo_deobfuscate(
    const struct woObfuscator *obfs,
    const woKey key,
    struct woPacketHeader *out_header,
    size_t packet_size
) {
    assert(packet_size <= obfs->buf_size);

    if (packet_size < WO_PACKET_HEADER_SIZE) {
        return false;
    }

    size_t offset = 0;

    // first xor the header and check it is valid
    {
        xor_buf(obfs->packet_buf, 0, WO_PACKET_HEADER_SIZE, key);

        // payload size
        out_header->payload_size = obfs->packet_buf[offset++] << 8;
        out_header->payload_size |= obfs->packet_buf[offset++];

        if (out_header->payload_size > packet_size - WO_PACKET_HEADER_SIZE) {
            return false;
        }

        // address
        memcpy(
            out_header->addr_port.addr,
            obfs->packet_buf + offset,
            sizeof out_header->addr_port.addr
        );
        offset += sizeof out_header->addr_port.addr;

        // port
        out_header->addr_port.port = obfs->packet_buf[offset++] << 8;
        out_header->addr_port.port |= obfs->packet_buf[offset++];
    }

    // xor the payload
    xor_buf(obfs->packet_buf, WO_PACKET_HEADER_SIZE, out_header->payload_size, key);

    return true;
}
