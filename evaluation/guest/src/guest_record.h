/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * guest_record - binary record written by the guest-side benchmark (rdrand_bench).
 *
 * rdrand_bench writes the RDRAND/RDSEED return values it observes inside the
 * guest as fixed-length records; the host-side rndlog-verify reads them to
 * match against the host JSONL (shared by both).
 *
 * Shared format for matching instruction type, width and value between the
 * guest and the host.
 */
#ifndef GUEST_RECORD_H
#define GUEST_RECORD_H

#include <stdint.h>

/* Values of the inst field (same assignment as the kernel's enum rndlog_inst) */
#define GUEST_INST_RDRAND  1
#define GUEST_INST_RDSEED  2

struct guest_record {
	uint64_t seq;		/* Global monotonically increasing sequence */
	uint32_t thread_id;	/* Executing thread ID (0-based) */
	uint8_t  inst;		/* GUEST_INST_RDRAND / GUEST_INST_RDSEED */
	uint8_t  bits;		/* Operand width: 16 / 32 / 64 */
	uint8_t  cf;		/* CF (1 = success) */
	uint8_t  reserved;	/* Padding (0) */
	uint64_t value;		/* Observed random value (masked to bits) */
};

#endif /* GUEST_RECORD_H */
