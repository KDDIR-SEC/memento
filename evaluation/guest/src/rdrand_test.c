/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rdrand_test.c - Phase 4 用 RDRAND/RDSEED 全レジスタ×全幅検証プログラム
 *
 * ゲスト内で実行し、各汎用レジスタ・各オペランド幅で RDRAND/RDSEED を発行して、
 * 改造 KVM が返す固定値（Phase 3）とフラグ（CF=1）、および x86-64 の幅セマンティクス
 * （64bit=全体 / 32bit=上位ゼロ拡張 / 16bit=下位のみ更新・上位保持）を検証する。
 *
 * 期待値（Phase 3 のハンドラが返す固定値）:
 *   RDRAND = 0x1122334455667788
 *   RDSEED = 0x8877665544332211
 *
 * 対象レジスタ: RAX,RCX,RDX,RBX,RSI,RDI,R8-R15（14個）。
 *   RSP/RBP はユーザー空間で安全に破壊できない（スタック/フレームポインタ）ため除外する。
 *   → 14 reg × 3 幅 × 2 命令 = 84 ケース。
 *
 * ビルド:
 *   make rdrand_test      （または gcc -O2 -mrdrnd -mrdseed -o rdrand_test rdrand_test.c）
 * 実行:
 *   ./rdrand_test
 *   ホスト側: sudo dmesg | grep kvm_rndlog
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
 * 1 ケースを実行する。
 *   INSN    : "rdrand" / "rdseed"
 *   MOD     : オペランド幅修飾子 ""=64bit / "k"=32bit / "w"=16bit
 *   REGNAME : 対象レジスタの 64bit 名（"rax" 等。register asm で物理レジスタを固定）
 *   BITS    : 表示用ビット幅
 *   EXPECT  : 期待されるレジスタ全体（64bit）の値
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

/* 1 レジスタについて RDRAND/RDSEED × 64/32/16bit の 6 ケースを検証 */
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
    printf("=== Phase 4: 全レジスタ×全幅 RDRAND/RDSEED 検証 ===\n");
    printf("期待固定値: RDRAND=0x%016lx  RDSEED=0x%016lx\n", RDRAND_FIXED, RDSEED_FIXED);
    printf("対象: RAX,RCX,RDX,RBX,RSI,RDI,R8-R15（14 レジスタ）× {16,32,64}bit × {RDRAND,RDSEED}\n");
    printf("除外: RSP/RBP（ユーザー空間で安全に破壊不可のため）\n\n");

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

    printf("\n結果: total=%d  PASS=%d  FAIL=%d\n", total, pass, fail);
    if (fail == 0)
        printf("=> 全ケース PASS（Phase 4 受け入れ）。ホスト側で sudo dmesg | grep kvm_rndlog を確認。\n");
    else
        printf("=> %d 件 FAIL。上記の不一致を確認してください。\n", fail);

    return fail == 0 ? 0 : 1;
}
