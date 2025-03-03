#ifndef WGOBFS_H
#define WGOBFS_H

#include <stdbool.h>
#include <stdlib.h>

#ifndef WO_MALLOC
#  define WO_MALLOC(c) malloc(c)
#endif

#ifndef WO_FREE
#  define WO_FREE(p) free(p)
#endif

enum woErrorCode {
    WO_ERR_OK,
    WO_ERR_MALLOC,
    WO_ERR_RAND,
    WO_ERR_IO,
};

typedef struct {
    enum woErrorCode code;
    int extended;
} woError;

bool wo_is_ok(const woError err);

typedef unsigned char woKey[8];

typedef unsigned char woIpAddr[16];

struct woAddrPort {
    woIpAddr addr;
    unsigned short port;
};

woError
wo_init_client(struct woClient **client, const struct woAddrPort *srv_addr, const woKey key);

void wo_dispose_client(struct woClient *client);

struct woServer;

enum woServerMode {
    WO_SERVER_ENDPOINT,
    WO_SERVER_PROXY,
};

woError wo_init_server(
    struct woServer **out_srv,
    enum woServerMode mode,
    const woKey key,
    unsigned short port,
    const struct woAddrPort *dest_addr
);

void wo_dispose_server(struct woServer *srv);

struct woClient;

#endif
