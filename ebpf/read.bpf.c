// SPDX-License-Identifier: GPL-2.0-only
//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

#define MAX_BUF_SIZE 128
#define MAX_PATH_SIZE 128
#define MEMENTO_S_IFMT 00170000
#define MEMENTO_S_IFCHR 0020000
#define MEMENTO_MINORBITS 20
#define MEMENTO_MINORMASK ((1U << MEMENTO_MINORBITS) - 1)
#define MEMENTO_RANDOM_MAJOR 1
#define MEMENTO_RANDOM_MINOR 8
#define MEMENTO_URANDOM_MINOR 9

typedef enum { EntryRead, ExitRead } Type;

struct read_entry_t {
    Type type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    int fd;
    __u64 count;
    char basename[MAX_PATH_SIZE];
    __u64 buf;  // uintptr_t
};

struct read_exit_t {
    Type type;
    __u32 pid;         // TID: unique per OS thread
    __u32 tgid;        // TGID: process ID (same for all threads in process)
    char comm[TASK_COMM_LEN];
    int fd;
    __u64 count;
    char basename[MAX_PATH_SIZE];
    __s64 bytes_read;
    char buf[MAX_BUF_SIZE];
};

// pid -> read_entry_t
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct read_entry_t);
    __uint(max_entries, 1024);
} read_entry_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline bool is_random_device(const char *name, __u16 mode,
                                             __u32 rdev) {
    bool random =
        name[0] == 'r' && name[1] == 'a' && name[2] == 'n' &&
        name[3] == 'd' && name[4] == 'o' && name[5] == 'm' &&
        name[6] == '\0';
    bool urandom =
        name[0] == 'u' && name[1] == 'r' && name[2] == 'a' &&
        name[3] == 'n' && name[4] == 'd' && name[5] == 'o' &&
        name[6] == 'm' && name[7] == '\0';
    __u32 major = rdev >> MEMENTO_MINORBITS;
    __u32 minor = rdev & MEMENTO_MINORMASK;

    return (mode & MEMENTO_S_IFMT) == MEMENTO_S_IFCHR &&
           major == MEMENTO_RANDOM_MAJOR &&
           ((random && minor == MEMENTO_RANDOM_MINOR) ||
            (urandom && minor == MEMENTO_URANDOM_MINOR));
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    // initialize entry_data
    struct read_entry_t data = {};
    data.type = EntryRead;
    data.pid = (__u32)bpf_get_current_pid_tgid();  // TID: unique per OS thread
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd = (int)ctx->args[0];
    data.buf = ctx->args[1];
    data.count = ctx->args[2];

    // retrieve fd
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    // BTF and BPF_CORE_READ cannot interpret the fd field of fdtable structure
    // because fd is a pointer to a pointer (struct file **fd),
    // So, I get a local copy fdtable data.
    struct fdtable fdt_local = {};
    struct file **fd_array;
    struct file *file_ptr;
    struct inode *inode;
    struct dentry *dentry;
    const char *name_ptr;
    __u32 rdev;
    __u16 mode;

    task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL) {
        // bpf_trace_printk("Could not get task information.");
        return 0;
    }

    if (bpf_probe_read_kernel(&files, sizeof(files), &task->files) < 0 ||
        files == NULL)
        return 0;
    if (bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt) < 0 ||
        fdt == NULL)
        return 0;
    if (bpf_probe_read_kernel(&fdt_local, sizeof(fdt_local), fdt) < 0)
        return 0;
    if (data.fd < 0 || (__u32)data.fd >= fdt_local.max_fds)
        return 0;
    if (bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt_local.fd) < 0 ||
        fd_array == NULL)
        return 0;
    if (bpf_probe_read_kernel(&file_ptr, sizeof(file_ptr),
                              &fd_array[data.fd]) < 0 || file_ptr == NULL)
        return 0;
    if (bpf_probe_read_kernel(&inode, sizeof(inode), &file_ptr->f_inode) < 0 ||
        inode == NULL)
        return 0;
    if (bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode) < 0 ||
        bpf_probe_read_kernel(&rdev, sizeof(rdev), &inode->i_rdev) < 0)
        return 0;

    if (bpf_probe_read_kernel(&dentry, sizeof(dentry),
                              &file_ptr->f_path.dentry) < 0 || dentry == NULL)
        return 0;
    if (bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr),
                              &dentry->d_name.name) < 0 || name_ptr == NULL)
        return 0;
    if (bpf_probe_read_kernel_str(&data.basename, sizeof(data.basename),
                                  name_ptr) < 0)
        return 0;

    // save entry_data
    if (is_random_device(data.basename, mode, rdev)) {
        bpf_map_update_elem(&read_entry_list, &data.pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid = (__u32)bpf_get_current_pid_tgid();  // TID: unique per OS thread

    struct read_entry_t *read_entry =
        bpf_map_lookup_elem(&read_entry_list, &pid);
    if (read_entry == NULL) {
        return 0;
    }

    struct read_exit_t exit_data = {};
    exit_data.type = ExitRead;

    exit_data.bytes_read = ctx->ret;
    if (exit_data.bytes_read <= 0) {
        bpf_map_delete_elem(&read_entry_list, &pid);
        return 0;
    }

    exit_data.pid = pid;
    exit_data.tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(exit_data.comm, sizeof(exit_data.comm));
    exit_data.fd = read_entry->fd;

    int capture_len = exit_data.bytes_read > MAX_BUF_SIZE ?
                      MAX_BUF_SIZE : (int)exit_data.bytes_read;
    if (bpf_probe_read_user(exit_data.buf, capture_len,
                            (const void *)read_entry->buf) < 0) {
        bpf_map_delete_elem(&read_entry_list, &pid);
        return 0;
    }

    exit_data.count = read_entry->count;
    bpf_probe_read_kernel(exit_data.basename, sizeof(exit_data.basename),
                          read_entry->basename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &exit_data,
                          sizeof(exit_data));

    bpf_map_delete_elem(&read_entry_list, &pid);

    return 0;
}
