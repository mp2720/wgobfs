#include "wgobfs.h"

bool wo_is_ok(woError err) {
    return err.code == WO_ERR_OK;
}
