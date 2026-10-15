/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rdrand_test_minimal.c - Phase 2 用 RDRAND/RDSEED VM-exit 発生確認プログラム
 *
 * ゲスト内で実行し、RDRAND 命令を N 回呼び出す。
 * ホスト側の dmesg で kvm_rndlog の VM-exit ログが出ることを確認するだけなので、
 * 返却値の正確性は確認しない。
 *
 * ビルド:
 *   gcc -O2 -o rdrand_test_minimal rdrand_test_minimal.c
 *
 * 実行:
 *   ./rdrand_test_minimal [count]
 *   例: ./rdrand_test_minimal 10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>  /* _rdrand64_step, _rdseed64_step */

static int do_rdrand(int count)
{
    unsigned long long val;
    int ok;
    int i;

    printf("RDRAND x%d:\n", count);
    for (i = 0; i < count; i++) {
        ok = _rdrand64_step(&val);
        if (ok)
            printf("  [%d] RDRAND => 0x%016llx (CF=1)\n", i, val);
        else
            printf("  [%d] RDRAND failed (CF=0)\n", i);
    }
    return 0;
}

static int do_rdseed(int count)
{
    unsigned long long val;
    int ok;
    int i;

    printf("RDSEED x%d:\n", count);
    for (i = 0; i < count; i++) {
        ok = _rdseed64_step(&val);
        if (ok)
            printf("  [%d] RDSEED => 0x%016llx (CF=1)\n", i, val);
        else
            printf("  [%d] RDSEED failed (CF=0)\n", i);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int count = 5;

    if (argc >= 2)
        count = atoi(argv[1]);
    if (count <= 0)
        count = 1;

    printf("=== Phase 2: VM-exit 発生確認 ===\n");
    printf("ホスト側で以下を実行して VM-exit ログを確認してください:\n");
    printf("  sudo dmesg | grep kvm_rndlog\n\n");

    do_rdrand(count);
    printf("\n");
    do_rdseed(count);

    printf("\n完了。ホスト側の dmesg を確認してください。\n");
    return 0;
}
