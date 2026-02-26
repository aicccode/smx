CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
SMX_DIR = ../../c
SMX_SRCS = $(SMX_DIR)/bigint256.c $(SMX_DIR)/sm3.c $(SMX_DIR)/sm4.c $(SMX_DIR)/sm2.c
CURL_FLAGS = $(shell pkg-config --cflags --libs libcurl)

all: demo

demo: main.c $(SMX_SRCS) $(SMX_DIR)/smx.h
	$(CC) $(CFLAGS) -I$(SMX_DIR) -o $@ main.c $(SMX_SRCS) $(CURL_FLAGS)

test: demo
	./demo

clean:
	rm -f demo

.PHONY: all test clean
