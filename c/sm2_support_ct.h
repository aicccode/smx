/* Constant-time compare, shared by sm2.c and the compiled-output check. */
#ifndef SMX_SM2_SUPPORT_CT_H
#define SMX_SM2_SUPPORT_CT_H

#include "smx_internal.h"

/* Constant-time comparison: the running time does not depend on where a difference is. */
static SMX_NOINLINE int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        /* the barrier keeps the optimizer from stopping once diff has all bits set */
        diff = (uint8_t)smx_ct_barrier(diff | (uint8_t)(a[i] ^ b[i]));
    }
    return diff == 0;
}

#endif /* SMX_SM2_SUPPORT_CT_H */
