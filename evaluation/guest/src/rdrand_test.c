/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rdrand_test.c - Phase 4 check of RDRAND/RDSEED for every register and width
 *
 * Runs inside the guest and issues RDRAND/RDSEED with each general-purpose
 * register and each operand width, and checks the fixed values returned by the
 * modified KVM (Phase 3), the flags (CF=1), and the x86-64 width semantics
 * (64-bit = whole register / 32-bit = upper half zero-extended / 16-bit = only
 * the low bits updated, upper bits preserved).
 *
 * Expected values (fixed values returned by the Phase 3 handler):
 *   RDRAND = 0x1122334455667788
 *   RDSEED = 0x8877665544332211
 *
 * Registers: RAX, RCX, RDX, RBX, RSI, RDI, R8-R15 (14).
 *   RSP/RBP are excluded because user space cannot safely clobber them (stack
 *   and frame pointers).
 *   -> 14 registers x 3 widths x 2 instructions = 84 cases.
 *
 * Build:
 *   make rdrand_test      (or gcc -O2 -mrdrnd -mrdseed -o rdrand_test rdrand_test.c)
 * Run:
 *   ./rdrand_test
 *   On the host: sudo dmesg | grep kvm_rndlog
 */

#include <stdio.h>
#include <stdint.h>

#define SENTINEL        0xAAAAAAAAAAAAAAAAUL
#define RDRAND_FIXED    0x1122334455667788UL
#define RDSEED_FIXED    0x8877665544332211UL
#define RFLAGS_CF       (1UL << 0)
#define RFLAGS_PF       (1UL << 2)
#define RFLAGS_AF       (1UL << 4)
#define RFLAGS_ZF       (1UL << 6)
#define RFLAGS_SF       (1UL << 7)
#define RFLAGS_OF       (1UL << 11)
#define RFLAGS_CLEARED  (RFLAGS_OF | RFLAGS_SF | RFLAGS_ZF | RFLAGS_AF | RFLAGS_PF)
#define RFLAGS_SEED     (2UL | RFLAGS_CLEARED)

static int total, pass, fail;

/*
 * Runs one case.
 *   INSN    : "rdrand" / "rdseed"
 *   MOD     : operand width modifier ""=64-bit / "k"=32-bit / "w"=16-bit
 *   REGNAME : 64-bit name of the target register ("rax" etc.; register asm
 *             pins the physical register)
 *   BITS    : bit width for display
 *   EXPECT  : expected value of the whole (64-bit) register
 */
#define CHECK_ONE(INSN, MOD, REGNAME, BITS, EXPECT)                         \
    do {                                                                    \
        register unsigned long _r asm(REGNAME) = SENTINEL;                  \
        unsigned long _flags = 0;                                           \
        unsigned long _seed = RFLAGS_SEED;                                  \
        asm volatile("pushq %2\n\t"                                         \
                     "popfq\n\t"                                           \
                     INSN " %" MOD "0\n\t"                                 \
                     "pushfq\n\t"                                          \
                     "popq %1"                                             \
                     : "+r"(_r), "=m"(_flags)                              \
                     : "r"(_seed)                                           \
                     : "cc", "memory");                                    \
        unsigned long got = _r;                                             \
        unsigned long exp = (EXPECT);                                       \
        unsigned long bad = _flags & RFLAGS_CLEARED;                        \
        total++;                                                            \
        if (got == exp && (_flags & RFLAGS_CF) != 0 && bad == 0) {          \
            pass++;                                                         \
        } else {                                                            \
            fail++;                                                         \
            printf("  [FAIL] %-6s %-4s %2dbit: got=0x%016lx "               \
                   "rflags=0x%lx expected=0x%016lx CF=1 "                  \
                   "OF/SF/ZF/AF/PF=0\n",                                   \
                   INSN, REGNAME, BITS, got, _flags, exp);                  \
        }                                                                   \
    } while (0)

/* Check the 6 cases RDRAND/RDSEED x 64/32/16-bit for one register */
#define CHECK_REG(REGNAME)                                                          \
    do {                                                                            \
        CHECK_ONE("rdrand", "",  REGNAME, 64, RDRAND_FIXED);                        \
        CHECK_ONE("rdrand", "k", REGNAME, 32, RDRAND_FIXED & 0xFFFFFFFFUL);         \
        CHECK_ONE("rdrand", "w", REGNAME, 16, (SENTINEL & ~0xFFFFUL) | (RDRAND_FIXED & 0xFFFFUL)); \
        CHECK_ONE("rdseed", "",  REGNAME, 64, RDSEED_FIXED);                        \
        CHECK_ONE("rdseed", "k", REGNAME, 32, RDSEED_FIXED & 0xFFFFFFFFUL);         \
        CHECK_ONE("rdseed", "w", REGNAME, 16, (SENTINEL & ~0xFFFFUL) | (RDSEED_FIXED & 0xFFFFUL)); \
    } while (0)

int main(void)
{
    printf("=== Phase 4: RDRAND/RDSEED check for every register and width ===\n");
    printf("Expected fixed values: RDRAND=0x%016lx  RDSEED=0x%016lx\n", RDRAND_FIXED, RDSEED_FIXED);
    printf("Targets: RAX,RCX,RDX,RBX,RSI,RDI,R8-R15 (14 registers) x {16,32,64}-bit x {RDRAND,RDSEED}\n");
    printf("Excluded: RSP/RBP (user space cannot safely clobber them)\n\n");

    CHECK_REG("rax");
    CHECK_REG("rcx");
    CHECK_REG("rdx");
    CHECK_REG("rbx");
    CHECK_REG("rsi");
    CHECK_REG("rdi");
    CHECK_REG("r8");
    CHECK_REG("r9");
    CHECK_REG("r10");
    CHECK_REG("r11");
    CHECK_REG("r12");
    CHECK_REG("r13");
    CHECK_REG("r14");
    CHECK_REG("r15");

    printf("\nResult: total=%d  PASS=%d  FAIL=%d\n", total, pass, fail);
    if (fail == 0)
        printf("=> All cases PASS (Phase 4 accepted). Check sudo dmesg | grep kvm_rndlog on the host.\n");
    else
        printf("=> %d case(s) FAIL. Check the mismatches above.\n", fail);

    return fail == 0 ? 0 : 1;
}
