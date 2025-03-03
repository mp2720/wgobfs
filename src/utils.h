#include "wgobfs.h"

#ifndef WO_UTILS_H
#  define WO_UTILS_H

#  define WO_ARR_LEN(arr) (sizeof(arr) / sizeof(*(arr)))

#  define WO_ERR(code_, extcode_)             \
      (woError) {                             \
          .code = code_, .extended = extcode_ \
      }

#  define WO_OK WO_ERR(WO_ERR_OK, 0)

#endif
