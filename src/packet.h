#ifndef WO_PACKET_H
#define WO_PACKET_H

#include "wgobfs.h"
#include <stddef.h>
#include <sys/types.h>

#define WO_PACKET_PAYLOAD_MAX_SIZE 65535
#define WO_PACKET_HEADER_SIZE 20

struct woBuffer {
    unsigned char *ptr;
    size_t capacity;
};

struct woObfuscator;

woError wo_obfuscator_init(struct woObfuscator **out_pb, size_t payload_mtu);

void wo_obfuscator_free(struct woObfuscator *pb);

struct woBuffer wo_obfuscator_get_payload_buf(struct woObfuscator *obfs);

struct woBuffer wo_obfuscator_get_packet_buf(struct woObfuscator *obfs);

struct woPacketHeader {
    struct woAddrPort addr_port;
    size_t payload_size;
};

size_t wo_obfuscate(
    struct woObfuscator *obfs,
    const woKey key,
    const struct woPacketHeader *header
);

bool wo_deobfuscate(
    const struct woObfuscator *obfs,
    const woKey key,
    struct woPacketHeader *out_header,
    size_t packet_size
);

#endif
