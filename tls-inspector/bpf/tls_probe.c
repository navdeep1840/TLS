// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define __TARGET_ARCH_x86 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* BPF map update flags */
#define BPF_ANY 0

#define MAX_PAYLOAD_SIZE 4096
#define MAX_PAYLOAD_MASK (MAX_PAYLOAD_SIZE - 1)
#define COMM_LEN 16

struct tls_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u64 cgroup_id;
    char comm[COMM_LEN];
    u8 function_type; // 0=SSL_write, 1=SSL_read, 2=SSL_write_ex, 3=SSL_read_ex
    u32 data_len;
    char data[MAX_PAYLOAD_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
} ssl_ctx_map SEC(".maps");

/*
 * data_len must be pre-validated by caller: > 0 and <= MAX_PAYLOAD_SIZE.
 * Taking u32 tells the verifier the size is unsigned.
 */
static __always_inline int process_ssl_data(const void *buf, u32 data_len,
                                            u8 func_type) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    if (pid == 0)
        return 0;

    /* Clamp data_len and apply mask so the verifier tracks the bound. */
    if (data_len > MAX_PAYLOAD_SIZE)
        data_len = MAX_PAYLOAD_SIZE;
    data_len &= MAX_PAYLOAD_MASK; /* verifier: [0, MAX_PAYLOAD_SIZE-1] */
    if (data_len == 0)
        return 0;

    struct tls_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp  = bpf_ktime_get_ns(); /* monotonic ns since boot; userspace converts */
    event->pid        = pid;
    event->tid        = tid;
    event->uid        = (u32)bpf_get_current_uid_gid();
    event->cgroup_id  = bpf_get_current_cgroup_id();
    event->function_type = func_type;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->data_len = data_len;
    if (bpf_probe_read_user(event->data, data_len, buf) < 0)
        event->data_len = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Clamp an unsigned 64-bit value from a register to a non-zero u32 size ≤
 * MAX_PAYLOAD_SIZE-1.  Returns 0 when the value is 0 (skip the event). */
static __always_inline u32 clamp_size(u64 raw) {
    if (raw == 0)
        return 0;
    /* Cap large values so the verifier sees a bounded, non-negative size. */
    if (raw >= MAX_PAYLOAD_SIZE)
        raw = MAX_PAYLOAD_SIZE - 1;
    u32 v = (u32)raw;
    v &= MAX_PAYLOAD_MASK; /* tell the verifier: v ∈ [1, MAX_PAYLOAD_SIZE-1] */
    return v;
}

/* SSL_write(SSL *ssl, const void *buf, int num) */
SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx) {
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    u64 raw = (u64)(long)PT_REGS_PARM3(ctx);
    u32 sz = clamp_size(raw);
    if (sz == 0)
        return 0;
    return process_ssl_data(buf, sz, 0);
}

/* SSL_read entry: store buf pointer keyed by pid_tgid */
SEC("uprobe/SSL_read")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr  = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_ctx_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/* SSL_read return: ret contains actual bytes read */
SEC("uretprobe/SSL_read")
int probe_ssl_read_ret(struct pt_regs *ctx) {
    u64 raw = (u64)(long)PT_REGS_RC(ctx);
    u32 sz  = clamp_size(raw);
    if (sz == 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *stored  = bpf_map_lookup_elem(&ssl_ctx_map, &pid_tgid);
    if (!stored)
        return 0;

    u64 buf_ptr = *stored;
    bpf_map_delete_elem(&ssl_ctx_map, &pid_tgid);
    return process_ssl_data((const void *)buf_ptr, sz, 1);
}

/* SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) */
SEC("uprobe/SSL_write_ex")
int probe_ssl_write_ex(struct pt_regs *ctx) {
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    u64 raw = (u64)PT_REGS_PARM3(ctx);
    u32 sz  = clamp_size(raw);
    if (sz == 0)
        return 0;
    return process_ssl_data(buf, sz, 2);
}

/* SSL_read_ex entry: store buf pointer keyed by pid_tgid */
SEC("uprobe/SSL_read_ex")
int probe_ssl_read_ex_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr  = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_ctx_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/* SSL_read_ex return: ret is 1 on success; actual bytes in *readbytes.
 * We can't easily access *readbytes here so use raw return to size-check. */
SEC("uretprobe/SSL_read_ex")
int probe_ssl_read_ex_ret(struct pt_regs *ctx) {
    /* SSL_read_ex returns 1 on success, 0 on failure — not a byte count.
     * We stored the requested num in ssl_ctx_map at entry; use that as size
     * since we can't access *readbytes from uretprobe without an extra map. */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *stored  = bpf_map_lookup_elem(&ssl_ctx_map, &pid_tgid);
    if (!stored)
        return 0;

    /* Check return value: 1 = success, 0 = failure */
    long rc = (long)PT_REGS_RC(ctx);
    if (rc != 1) {
        bpf_map_delete_elem(&ssl_ctx_map, &pid_tgid);
        return 0;
    }

    u64 buf_ptr = *stored;
    bpf_map_delete_elem(&ssl_ctx_map, &pid_tgid);

    /* We don't know actual bytes read without a second map entry for *readbytes.
     * Capture up to MAX_PAYLOAD_SIZE as a best-effort snapshot. */
    u32 sz = MAX_PAYLOAD_SIZE - 1;
    return process_ssl_data((const void *)buf_ptr, sz, 3);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
