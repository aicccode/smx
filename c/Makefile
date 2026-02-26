CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99

SRCS = bigint256.c sm3.c sm4.c sm2.c
OBJS = $(SRCS:.c=.o)

all: test_all

%.o: %.c smx.h
	$(CC) $(CFLAGS) -c $< -o $@

test_all: test_all.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

test: test_all
	./test_all

clean:
	rm -f *.o test_all

.PHONY: all test clean
