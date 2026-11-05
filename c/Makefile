CC = gcc
# No -march=native on purpose: the SIMD paths are selected at run time.
CFLAGS = -Wall -Wextra -O3 -std=c99

SRCS = bigint256.c sm3.c sm4.c sm2.c
HDRS = smx.h smx_internal.h sm2_fp.h sm2_fn.h sm2_ec.h sm2_precomp.inc
OBJS = $(SRCS:.c=.o)

all: test_all

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

test_all: test_all.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

test_kat: test_kat.c test_kat_vectors.h $(OBJS)
	$(CC) $(CFLAGS) -o $@ test_kat.c $(OBJS)

test_internal: test_internal.c $(HDRS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ test_internal.c $(OBJS)

bench: bench.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ bench.c $(OBJS)

test: test_all test_kat test_internal
	./test_all
	./test_kat
	./test_internal

# Runs every test against each compile-time fallback: the portable 128-bit-free
# multiply, no x86 SIMD at all, and every SM4 tier.
FALLBACKS = -DSMX_NO_INT128 -DSMX_NO_SIMD "-DSMX_NO_INT128 -DSMX_NO_SIMD" \
	-DSMX_SM4_MAX_TIER=0 -DSMX_SM4_MAX_TIER=1 -DSMX_SM4_MAX_TIER=2 -DSMX_SM4_MAX_TIER=3
check-fallbacks:
	@set -e; for f in $(FALLBACKS); do \
		echo "=== $$f"; \
		for t in test_all test_kat test_internal; do \
			$(CC) $(CFLAGS) $$f -o /tmp/smx_fallback_$$t $$t.c $(SRCS); \
			/tmp/smx_fallback_$$t | tail -1; \
		done; \
	done

check-sanitizers:
	@set -e; for t in test_all test_kat test_internal; do \
		$(CC) -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined \
			-fno-sanitize-recover=all -o /tmp/smx_san_$$t $$t.c $(SRCS); \
		/tmp/smx_san_$$t | tail -1; \
	done

# Secret-dependent branches and addresses, detected with MemorySanitizer. Capped at
# SM4 tier 2 because clang's MSan rejects the GFNI intrinsics outright. Tier 3 shares
# all of its structure with tier 2 and differs only in the S-box instructions.
check-ct:
	clang -std=gnu99 -O2 -g -DSMX_CT_TEST -DSMX_SM4_MAX_TIER=2 -fsanitize=memory -fno-sanitize-memory-param-retval -fno-sanitize-recover=all \
		-o /tmp/smx_ct test_ct.c bigint256.c sm3.c
	/tmp/smx_ct

format:
	clang-format -i *.c smx.h smx_internal.h sm2_fp.h sm2_fn.h sm2_ec.h tools/*.c

clean:
	rm -f *.o test_all test_kat test_internal bench

.PHONY: all test check-fallbacks check-sanitizers check-ct format clean
