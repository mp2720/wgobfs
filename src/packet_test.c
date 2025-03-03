#include "packet.h"
#include "utils.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TESTS 2500

static unsigned char buf[WO_PACKET_HEADER_SIZE + WO_PACKET_PAYLOAD_MAX_SIZE];
unsigned int seed;

static void rand_key(woKey key) {
    for (size_t i = 0; i < sizeof(woKey); ++i) {
        key[i] = rand_r(&seed);
    }
}

static void rand_addr_port(struct woAddrPort *addr_port) {
    addr_port->port = rand_r(&seed);
    for (size_t i = 0; i < sizeof addr_port->addr; ++i) {
        addr_port->addr[i] = rand_r(&seed);
    }
}

static void rand_packet_data(struct woPacketHeader *ph, unsigned char *payload_ptr) {
    for (size_t i = 0; i < ph->payload_size; ++i) {
        payload_ptr[i] = rand_r(&seed);
    }
}

// Check deobfuscation is reverse of obfuscation.
static void test_valid(size_t payload_mtu, size_t payload_size) {
    struct woObfuscator *obfs;
    woError err = wo_obfuscator_init(&obfs, payload_mtu);
    assert(wo_is_ok(err) && "failed to init obfuscator");

    const struct woBuffer payload_buf = wo_obfuscator_get_payload_buf(obfs),
                          packet_buf = wo_obfuscator_get_packet_buf(obfs);

    woKey key;
    rand_key(key);

    struct woPacketHeader ph1;
    ph1.payload_size = payload_size;
    rand_addr_port(&ph1.addr_port);

    rand_packet_data(&ph1, payload_buf.ptr);

    // save payload to another buffer for later comparasion
    memcpy(buf, payload_buf.ptr, ph1.payload_size);

    // test
    const size_t packet_size = wo_obfuscate(obfs, key, &ph1);
    assert(packet_size <= packet_buf.capacity);
    assert(packet_size >= WO_PACKET_HEADER_SIZE + ph1.payload_size);

    struct woPacketHeader ph2;
    assert(wo_deobfuscate(obfs, key, &ph2, packet_size));

    assert(ph1.payload_size == ph2.payload_size);
    assert(memcmp(&ph1.addr_port.addr, &ph2.addr_port.addr, sizeof ph1.addr_port.addr) == 0);
    assert(ph1.addr_port.port == ph2.addr_port.port);
    assert(memcmp(buf, payload_buf.ptr, ph2.payload_size) == 0);

    wo_obfuscator_free(obfs);
};

int main(void) {
    seed = time(NULL);
    fprintf(stderr, "test src/packet.c with seed %jd\n", (intmax_t)seed);
    fflush(stderr);

    // valid
    {
        test_valid(0, 0);
        test_valid(WO_PACKET_PAYLOAD_MAX_SIZE, WO_PACKET_PAYLOAD_MAX_SIZE);

        for (int i = 0; i < TESTS; ++i) {
            const size_t payload_mtu = rand_r(&seed) % (WO_PACKET_PAYLOAD_MAX_SIZE + 1);
            const size_t payload_size = rand_r(&seed) % (payload_mtu + 1);

            test_valid(payload_mtu, payload_size);
        }
    }

    // invalid
    {
        const size_t packet_size = 8192;

        struct woObfuscator *obfs;
        wo_obfuscator_init(&obfs, packet_size - WO_PACKET_HEADER_SIZE);

        woKey key;
        rand_key(key);

        // Test on too small input size
        struct woPacketHeader ph;
        assert(!wo_deobfuscate(obfs, key, &ph, WO_PACKET_HEADER_SIZE - 1));

        // Test on payload size bigger than `pb.size`
        struct woBuffer packet_buf = wo_obfuscator_get_packet_buf(obfs);
        packet_buf.ptr[0] = 0xff ^ key[0];
        packet_buf.ptr[0] = 0xff ^ key[0];
        assert(!wo_deobfuscate(obfs, key, &ph, packet_size));

        // Check no crash happens on junk data
        // Run with sanitizers
        for (int i = 0; i < TESTS; ++i) {
            for (size_t i = 0; i < packet_size; ++i) {
                packet_buf.ptr[i] = rand_r(&seed);
            }

            rand_key(key);

            const size_t input_size =
                WO_PACKET_HEADER_SIZE + (rand_r(&seed) % (packet_size - WO_PACKET_HEADER_SIZE + 1));

            wo_deobfuscate(obfs, key, &ph, input_size);
        }

        wo_obfuscator_free(obfs);
    }
}
