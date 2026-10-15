// SPDX-License-Identifier: GPL-2.0-only
/*
 * rdrand_bench.c - Phase 7 評価用 RDRAND/RDSEED ベンチマーク（ゲスト内実行）
 *
 * RDRAND/RDSEED を大量回数実行し、観測した値を struct guest_record の
 * バイナリ列としてファイルへ書き出す。ホスト側 rndlog-verify がこのログと
 * ホスト JSONL を照合して捕捉率を算出する。経過時間・ns/op は stderr に出す。
 *
 * 評価パターン:
 *   A: --inst rdrand --bits 64       単純ループ
 *   B: --inst rdseed --bits 64       単純ループ
 *   C: --inst both   --bits all      16/32/64 混在
 *   D: --threads T                   マルチスレッド
 *
 * ビルド: make bench   （gcc -O2 -mrdrnd -mrdseed -pthread）
 * 例: ./rdrand_bench --inst rdrand --bits 64 --count 1000000 --output guest_values.bin
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <immintrin.h>

#include "guest_record.h"

enum inst_sel { SEL_RDRAND, SEL_RDSEED, SEL_BOTH };
enum bits_sel { BITS_16, BITS_32, BITS_64, BITS_ALL };

struct opts {
	enum inst_sel inst;
	enum bits_sel bits;
	uint64_t count;		/* 全スレッド合計の実行回数 */
	int threads;
	uint64_t rate;		/* 発行レート上限 ops/sec（全スレッド合計、0=無制限） */
	int pin_base;		/* -1=固定なし、それ以外は base+thread_id へ固定 */
};

/* ペーシング判定の間隔（命令数, 2 の冪）。毎命令の nanosleep は粒度が粗く高コストなので
 * この間隔ごとに目標経過時刻と比較して先行分だけ待つ。 */
#define PACE_CHUNK 1024u

static double ts_diff(const struct timespec *a, const struct timespec *b);

/* グローバル seq（スレッド間で単調増加） */
static uint64_t g_seq;
static pthread_mutex_t g_seq_lock = PTHREAD_MUTEX_INITIALIZER;

struct worker {
	pthread_t tid;
	int thread_id;
	const struct opts *o;
	uint64_t n;			/* このスレッドの実行回数 */
	struct guest_record *recs;	/* 出力（n 件） */
	int affinity_error;
};

/* 1 命令を実行し、観測値と CF を返す。bits は 16/32/64 */
static int do_one(int is_rdseed, int bits, uint64_t *out)
{
	int ok;

	if (bits == 16) {
		unsigned short v = 0;

		ok = is_rdseed ? _rdseed16_step(&v) : _rdrand16_step(&v);
		*out = v;
	} else if (bits == 32) {
		unsigned int v = 0;

		ok = is_rdseed ? _rdseed32_step(&v) : _rdrand32_step(&v);
		*out = v;
	} else {
		unsigned long long v = 0;

		ok = is_rdseed ? _rdseed64_step(&v) : _rdrand64_step(&v);
		*out = v;
	}
	return ok;
}

static void *worker_fn(void *arg)
{
	struct worker *w = arg;
	const struct opts *o = w->o;
	const int bits_cycle[3] = { 16, 32, 64 };
	uint64_t i;
	/* レート制御: このスレッドの目標 ops/sec（全体 rate をスレッド数で按分）。0=無制限。 */
	double per_rate = (o->rate > 0) ? (double)o->rate / (double)o->threads : 0.0;
	struct timespec wstart;
	if (o->pin_base >= 0) {
		cpu_set_t set;
		int target = o->pin_base + w->thread_id;

		if (target >= CPU_SETSIZE) {
			w->affinity_error = EINVAL;
			return NULL;
		}
		CPU_ZERO(&set);
		CPU_SET(target, &set);
		w->affinity_error = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
		if (w->affinity_error != 0 || sched_getcpu() != target) {
			w->affinity_error = w->affinity_error ? w->affinity_error : EXDEV;
			return NULL;
		}
	}

	if (per_rate > 0.0)
		clock_gettime(CLOCK_MONOTONIC, &wstart);

	for (i = 0; i < w->n; i++) {
		int is_rdseed;
		int bits;
		uint64_t val = 0, seq;
		int ok;

		/* 命令選択 */
		if (o->inst == SEL_RDRAND)
			is_rdseed = 0;
		else if (o->inst == SEL_RDSEED)
			is_rdseed = 1;
		else
			is_rdseed = (int)(i & 1);	/* both: 交互 */

		/* 幅選択 */
		if (o->bits == BITS_ALL)
			bits = bits_cycle[i % 3];
		else if (o->bits == BITS_16)
			bits = 16;
		else if (o->bits == BITS_32)
			bits = 32;
		else
			bits = 64;

		ok = do_one(is_rdseed, bits, &val);

		pthread_mutex_lock(&g_seq_lock);
		seq = g_seq++;
		pthread_mutex_unlock(&g_seq_lock);

		w->recs[i].seq = seq;
		w->recs[i].thread_id = (uint32_t)w->thread_id;
		w->recs[i].inst = is_rdseed ? GUEST_INST_RDSEED : GUEST_INST_RDRAND;
		w->recs[i].bits = (uint8_t)bits;
		w->recs[i].cf = (uint8_t)(ok ? 1 : 0);
		w->recs[i].reserved = 0;
		w->recs[i].value = val;

		/* PACE_CHUNK 命令ごとに目標経過時刻へペーシング（先行していれば待つ） */
		if (per_rate > 0.0 && (i & (PACE_CHUNK - 1)) == (PACE_CHUNK - 1)) {
			struct timespec now;
			double elapsed, target;

			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed = ts_diff(&wstart, &now);	/* 経過秒 */
			target = (double)(i + 1) / per_rate;	/* この時点での目標秒 */
			if (target > elapsed) {
				double d = target - elapsed;
				struct timespec ts;

				ts.tv_sec = (time_t)d;
				ts.tv_nsec = (long)((d - (double)ts.tv_sec) * 1e9);
				nanosleep(&ts, NULL);
			}
		}
	}
	return NULL;
}

static double ts_diff(const struct timespec *a, const struct timespec *b)
{
	return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

int main(int argc, char *argv[])
{
	struct opts o = { .inst = SEL_RDRAND, .bits = BITS_64, .count = 1000000, .threads = 1, .rate = 0, .pin_base = -1 };
	const char *out_path = "guest_values.bin";
	struct worker *ws;
	struct timespec t0, t1;
	FILE *fp;
	int output_fd;
	uint64_t total = 0, cf0 = 0;
	int opt, t, created = 0, thread_error = 0;

	static const struct option lo[] = {
		{ "inst",    required_argument, 0, 'i' },
		{ "bits",    required_argument, 0, 'b' },
		{ "count",   required_argument, 0, 'c' },
		{ "threads", required_argument, 0, 't' },
		{ "output",  required_argument, 0, 'o' },
		{ "rate",    required_argument, 0, 'r' },
		{ "pin-base", required_argument, 0, 'p' },
		{ "help",    no_argument,       0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "i:b:c:t:o:r:p:h", lo, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (!strcmp(optarg, "rdrand")) o.inst = SEL_RDRAND;
			else if (!strcmp(optarg, "rdseed")) o.inst = SEL_RDSEED;
			else if (!strcmp(optarg, "both")) o.inst = SEL_BOTH;
			else { fprintf(stderr, "bad --inst\n"); return 2; }
			break;
		case 'b':
			if (!strcmp(optarg, "16")) o.bits = BITS_16;
			else if (!strcmp(optarg, "32")) o.bits = BITS_32;
			else if (!strcmp(optarg, "64")) o.bits = BITS_64;
			else if (!strcmp(optarg, "all")) o.bits = BITS_ALL;
			else { fprintf(stderr, "bad --bits\n"); return 2; }
			break;
		case 'c': o.count = strtoull(optarg, NULL, 0); break;
		case 't': o.threads = atoi(optarg); break;
		case 'o': out_path = optarg; break;
		case 'r': o.rate = strtoull(optarg, NULL, 0); break;
		case 'p': o.pin_base = atoi(optarg); break;
		case 'h':
		default:
			fprintf(stderr,
				"usage: %s [--inst rdrand|rdseed|both] [--bits 16|32|64|all]\n"
				"          [--count N] [--threads T] [--output FILE] [--rate OPS_PER_SEC] [--pin-base CPU]\n"
				"  --rate 0（既定）=無制限（性能測定用）。>0 で発行レートを抑制（捕捉精度測定用）。\n",
				argv[0]);
			return (opt == 'h') ? 0 : 2;
		}
	}
	if (o.threads < 1)
		o.threads = 1;
	if (o.count < (uint64_t)o.threads)
		o.count = o.threads;

	if (o.threads > CPU_SETSIZE || o.pin_base < -1 ||
	    (o.pin_base >= 0 && o.pin_base > CPU_SETSIZE - o.threads)) {
		fprintf(stderr, "invalid --pin-base/--threads combination\n");
		return 2;
	}

	ws = calloc((size_t)o.threads, sizeof(*ws));
	if (!ws) { perror("calloc"); return 1; }

	/* 各スレッドへ件数を分配（余りは先頭スレッドへ） */
	for (t = 0; t < o.threads; t++) {
		ws[t].thread_id = t;
		ws[t].o = &o;
		ws[t].n = o.count / (uint64_t)o.threads;
		if (t == 0)
			ws[t].n += o.count % (uint64_t)o.threads;
		ws[t].recs = calloc(ws[t].n, sizeof(struct guest_record));
		if (!ws[t].recs) { perror("calloc recs"); return 1; }
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (t = 0; t < o.threads; t++) {
		int rc = pthread_create(&ws[t].tid, NULL, worker_fn, &ws[t]);

		if (rc != 0) {
			thread_error = rc;
			fprintf(stderr, "pthread_create failed: %s\n", strerror(rc));
			break;
		}
		created++;
	}
	for (t = 0; t < created; t++) {
		int rc = pthread_join(ws[t].tid, NULL);

		if (rc != 0 && thread_error == 0)
			thread_error = rc;
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);
	if (thread_error != 0) {
		for (t = 0; t < o.threads; t++)
			free(ws[t].recs);
		free(ws);
		return 1;
	}

	for (t = 0; t < o.threads; t++) {
		if (ws[t].affinity_error != 0) {
			fprintf(stderr, "thread %d affinity failed: %s\n", t,
				strerror(ws[t].affinity_error));
			return 1;
		}
	}
	/* バイナリ書き出し */
	output_fd = open(out_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (output_fd < 0) { perror("open output"); return 1; }
	if (fchmod(output_fd, 0600) != 0) { perror("chmod output"); close(output_fd); return 1; }
	fp = fdopen(output_fd, "wb");
	if (!fp) {
		perror("fdopen output");
		close(output_fd);
		return 1;
	}
	for (t = 0; t < o.threads; t++) {
		if (fwrite(ws[t].recs, sizeof(struct guest_record), ws[t].n, fp) != ws[t].n) {
			perror("fwrite");
			fclose(fp);
			return 1;
		}
		total += ws[t].n;
		for (uint64_t i = 0; i < ws[t].n; i++)
			if (!ws[t].recs[i].cf)
				cf0++;
	}
	fclose(fp);

	{
		double sec = ts_diff(&t0, &t1);

		fprintf(stderr,
			"rdrand_bench: count=%llu threads=%d time=%.4fs ns/op=%.1f cf0=%llu output=%s\n",
			(unsigned long long)total, o.threads, sec,
			total ? sec * 1e9 / (double)total : 0.0,
			(unsigned long long)cf0, out_path);
		/* run-benchmark.sh がパースしやすい機械可読行も出す */
		printf("BENCH count=%llu threads=%d time_s=%.6f ns_per_op=%.3f cf0=%llu\n",
		       (unsigned long long)total, o.threads, sec,
		       total ? sec * 1e9 / (double)total : 0.0,
		       (unsigned long long)cf0);
	}

	for (t = 0; t < o.threads; t++)
		free(ws[t].recs);
	free(ws);
	return cf0 == 0 ? 0 : 1;
}
