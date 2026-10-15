# SPDX-License-Identifier: GPL-2.0-only

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -mrdrnd -mrdseed

SRCS_MINIMAL = src/rdrand_test_minimal.c
BIN_MINIMAL  = rdrand_test_minimal

SRCS_FULL    = src/rdrand_test.c
BIN_FULL     = rdrand_test

SRCS_BENCH   = src/rdrand_bench.c
BIN_BENCH    = rdrand_bench

SRCS_SYSCALL = src/syscall_probe.c
BIN_SYSCALL  = syscall_probe

.PHONY: all minimal full bench syscall clean

all: minimal full bench syscall

minimal: $(BIN_MINIMAL)

full: $(BIN_FULL)

bench: $(BIN_BENCH)

syscall: $(BIN_SYSCALL)

$(BIN_MINIMAL): $(SRCS_MINIMAL)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_FULL): $(SRCS_FULL)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_BENCH): $(SRCS_BENCH) src/guest_record.h
	$(CC) $(CFLAGS) -pthread -o $@ $(SRCS_BENCH)

$(BIN_SYSCALL): $(SRCS_SYSCALL)
	$(CC) -O2 -Wall -Wextra -Werror -pthread -o $@ $^

clean:
	rm -f $(BIN_MINIMAL) $(BIN_FULL) $(BIN_BENCH) $(BIN_SYSCALL)
