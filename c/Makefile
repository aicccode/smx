CC = gcc
# No -march=native on purpose: the SIMD paths are selected at run time.
CFLAGS = -Wall -Wextra -O3 -std=c99

SRCS = bigint256.c sm3.c sm4.c sm2.c
HDRS = smx.h smx_internal.h sm2_fp.h sm2_fn.h sm2_ec.h sm2_precomp.inc sm4_sbox_circuit.inc \
	sm2_point.inc sm2_support.inc sm2_key_exchange.inc sm2_support_ct.h
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

# Includes sm4.c itself, to reach the S-box internals.
test_security: test_security.c $(HDRS) bigint256.o sm3.o sm2.o sm4.c
	$(CC) $(CFLAGS) -o $@ test_security.c bigint256.o sm3.o sm2.o

bench: bench.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ bench.c $(OBJS)

test: test_all test_kat test_internal test_security
	./test_all
	./test_kat
	./test_internal
	./test_security

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
		$(CC) $(CFLAGS) $$f -o /tmp/smx_fallback_sec test_security.c bigint256.c sm3.c sm2.c; \
		/tmp/smx_fallback_sec | tail -1; \
	done
	@for f in -DSMX_TEST_RNG_FAILS -DSMX_TEST_RNG_ALL_ONES; do \
		$(CC) $(CFLAGS) $$f -o /tmp/smx_rng test_rng_failure.c $(SRCS) && /tmp/smx_rng | tail -1; \
	done

check-sanitizers:
	@set -e; for t in test_all test_kat test_internal; do \
		$(CC) -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined \
			-fno-sanitize-recover=all -o /tmp/smx_san_$$t $$t.c $(SRCS); \
		/tmp/smx_san_$$t | tail -1; \
	done; \
	$(CC) -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined \
		-fno-sanitize-recover=all -o /tmp/smx_san_sec test_security.c bigint256.c sm3.c sm2.c; \
	/tmp/smx_san_sec | tail -1

# Secret-dependent branches and addresses: the compiled code's branch shapes
# (tools/check_ct_asm.py), a single-stepped instruction trace compared between secret inputs
# (tools/check_ct_trace.sh; control flow only), then MemorySanitizer. Capped at
# SM4 tier 2 because clang's MSan rejects the GFNI intrinsics outright. Tier 3 shares
# all of its structure with tier 2 and differs only in the S-box instructions.
check-ct:
	python3 tools/check_ct_asm.py
	tools/check_ct_trace.sh
	@for tier in 2 1 0; do \
		clang -std=gnu99 -O2 -g -DSMX_CT_TEST -DSMX_SM4_MAX_TIER=$$tier -fsanitize=memory \
			-fno-sanitize-memory-param-retval -fno-sanitize-recover=all \
			-o /tmp/smx_ct test_ct.c bigint256.c sm3.c && \
		MSAN_OPTIONS=intercept_strlen=0 /tmp/smx_ct || exit 1; \
	done

# clang libFuzzer with ASan and UBSan, one target over every public entry point.
fuzz: fuzz_all

fuzz_all: fuzz/fuzz_all.c $(SRCS) $(HDRS)
	clang -std=gnu99 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -I. \
		-o fuzz_all fuzz/fuzz_all.c $(SRCS)

format:
	clang-format -i *.c smx.h smx_internal.h sm2_fp.h sm2_fn.h sm2_ec.h sm2_support_ct.h sm2_point.inc sm2_support.inc \
		sm2_key_exchange.inc tools/*.c fuzz/*.c

clean:
	rm -f *.o test_all test_kat test_internal test_security bench fuzz_all

.PHONY: all test check-fallbacks check-sanitizers check-ct fuzz format clean
