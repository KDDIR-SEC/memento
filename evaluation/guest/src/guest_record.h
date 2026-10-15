/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * guest_record - ゲスト側ベンチ（rdrand_bench）が記録するバイナリレコード。
 *
 * rdrand_bench がゲスト内で観測した RDRAND/RDSEED の返却値を固定長で書き出し、
 * ホスト側 rndlog-verify がホスト JSONL と照合するために読み込む（両者で共有）。
 *
 * ゲスト側とホスト側の命令種別・幅・値を照合するための共有形式。
 */
#ifndef GUEST_RECORD_H
#define GUEST_RECORD_H

#include <stdint.h>

/* inst フィールドの値（kernel 側 enum rndlog_inst と同じ割り当て） */
#define GUEST_INST_RDRAND  1
#define GUEST_INST_RDSEED  2

struct guest_record {
	uint64_t seq;		/* グローバル単調増加シーケンス */
	uint32_t thread_id;	/* 実行スレッド ID（0 起点） */
	uint8_t  inst;		/* GUEST_INST_RDRAND / GUEST_INST_RDSEED */
	uint8_t  bits;		/* オペランド幅: 16 / 32 / 64 */
	uint8_t  cf;		/* CF（1=成功） */
	uint8_t  reserved;	/* パディング（0） */
	uint64_t value;		/* 観測した乱数値（bits でマスク済み） */
};

#endif /* GUEST_RECORD_H */
