# SPDX-License-Identifier: GPL-2.0-only

CC      = gcc
# guest_record.h（struct guest_record 共有）を include
GR_INC := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../guest/src)
CFLAGS  = -O2 -Wall -Wextra -I$(GR_INC)

SRCS = src/rndlog-verify.c
BIN  = rndlog-verify

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(BIN)
