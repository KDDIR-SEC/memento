// SPDX-License-Identifier: GPL-2.0-only
//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

#define MAX_BUF_SIZE 128
#define MAX_PATH_SIZE 128

typedef enum { EntryGetrandom, ExitGetrandom } Type;

struct getrandom_entry_t {
    Type type;
    __u32 pid;
    unsigned int flags;
    char comm[TASK_COMM_LEN];
    __u64 len;
    __u64 ubuf;
};

struct getrandom_exit_t {
    Type type;
    __u32 pid;   // TID
    __u32 tgid;  // process ID
    unsigned int flags;
    char comm[TASK_COMM_LEN];
    __u64 len;
    __s64 bytes_read;
    char ubuf[MAX_BUF_SIZE];
};

// tid -> getrandom_entry_t
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct getrandom_entry_t);
    __uint(max_entries, 1024);
} getrandom_entry_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getrandom")
int handle_sys_enter_getrandom(struct trace_event_raw_sys_enter *ctx) {
    struct getrandom_entry_t data = {};
    data.type = EntryGetrandom;
    data.pid = (__u32)bpf_get_current_pid_tgid();
    data.flags = (unsigned int)ctx->args[2];
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ubuf = ctx->args[0];
    data.len = ctx->args[1];

    // save and submit entry_data
    bpf_map_update_elem(&getrandom_entry_list, &data.pid, &data, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getrandom")
int handle_sys_exit_getrandom(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = (__u32)bpf_get_current_pid_tgid();

    struct getrandom_entry_t *getrandom_entry =
        bpf_map_lookup_elem(&getrandom_entry_list, &pid);
    if (getrandom_entry == NULL) {
        return 0;
    }

    struct getrandom_exit_t exit_data = {};
    exit_data.type = ExitGetrandom;

    exit_data.bytes_read = ctx->ret;
    if (exit_data.bytes_read <= 0) {
        bpf_map_delete_elem(&getrandom_entry_list, &pid);
        return 0;
    }

    exit_data.pid = pid;
    exit_data.tgid = bpf_get_current_pid_tgid() >> 32;
    exit_data.flags = getrandom_entry->flags;
    bpf_get_current_comm(exit_data.comm, sizeof(exit_data.comm));

    int capture_len = exit_data.bytes_read > MAX_BUF_SIZE ? MAX_BUF_SIZE : (int)exit_data.bytes_read;
    if (bpf_probe_read_user(exit_data.ubuf, capture_len,
                            (const void *)getrandom_entry->ubuf) < 0) {
        bpf_map_delete_elem(&getrandom_entry_list, &pid);
        return 0;
    }

    exit_data.len = getrandom_entry->len;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &exit_data,
                          sizeof(exit_data));

    bpf_map_delete_elem(&getrandom_entry_list, &pid);

    return 0;
}
