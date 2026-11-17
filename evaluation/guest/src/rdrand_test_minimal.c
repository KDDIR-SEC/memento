/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rdrand_test_minimal.c - Phase 2 check that RDRAND/RDSEED cause VM exits
 *
 * Runs inside the guest and executes the RDRAND instruction N times.
 * It only confirms that the host's dmesg shows kvm_rndlog VM-exit logs, so it
 * does not check that the returned values are correct.
 *
 * Build:
 *   gcc -O2 -o rdrand_test_minimal rdrand_test_minimal.c
 *
 * Run:
 *   ./rdrand_test_minimal [count]
 *   Example: ./rdrand_test_minimal 10
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

    printf("=== Phase 2: VM-exit check ===\n");
    printf("Run the following on the host and check the VM-exit logs:\n");
    printf("  sudo dmesg | grep kvm_rndlog\n\n");

    do_rdrand(count);
    printf("\n");
    do_rdseed(count);

    printf("\nDone. Check dmesg on the host.\n");
    return 0;
}
