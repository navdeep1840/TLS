// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#define __TARGET_ARCH_x86_64 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PAYLOAD_SIZE 4096
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
    __type(key, u64);
    __type(value, u64);
} ssl_ctx_map SEC(".maps");

static __always_inline int process_ssl_data(struct pt_regs *ctx, void *ssl_ctx, 
                                           const void *buf, int num, u8 func_type) {
    struct tls_event *event;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->function_type = func_type;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    u32 read_size = num < MAX_PAYLOAD_SIZE ? num : MAX_PAYLOAD_SIZE;
    event->data_len = read_size;
    
    // Safely read user memory
    int ret = bpf_probe_read_user(event->data, read_size, buf);
    if (ret < 0) {
        event->data_len = 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/SSL_write")
int BPF_KPROBE(probe_ssl_write, void *ssl, const void *buf, int num) {
    return process_ssl_data(ctx, ssl, buf, num, 0);
}

// SSL_read(SSL *ssl, void *buf, int num)
SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(probe_ssl_read_ret, int ret) {
    if (ret <= 0)
        return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr;
    
    // Try to get buffer pointer from stored context
    u64 *stored_buf = bpf_map_lookup_elem(&ssl_ctx_map, &pid_tgid);
    if (!stored_buf)
        return 0;
    
    buf_ptr = *stored_buf;
    bpf_map_delete_elem(&ssl_ctx_map, &pid_tgid);
    
    return process_ssl_data(ctx, NULL, (void *)buf_ptr, ret, 1);
}

SEC("uprobe/SSL_read")
int BPF_KPROBE(probe_ssl_read, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr = (u64)buf;
    bpf_map_update_elem(&ssl_ctx_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

// SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
SEC("uprobe/SSL_write_ex")
int BPF_KPROBE(probe_ssl_write_ex, void *ssl, const void *buf, size_t num, size_t *written) {
    return process_ssl_data(ctx, ssl, buf, (int)num, 2);
}

// SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
SEC("uretprobe/SSL_read_ex")
int BPF_KRETPROBE(probe_ssl_read_ex_ret, int ret) {
    if (ret <= 0)
        return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *stored_buf = bpf_map_lookup_elem(&ssl_ctx_map, &pid_tgid);
    if (!stored_buf)
        return 0;
    
    u64 buf_ptr = *stored_buf;
    bpf_map_delete_elem(&ssl_ctx_map, &pid_tgid);
    
    return process_ssl_data(ctx, NULL, (void *)buf_ptr, ret, 3);
}

SEC("uprobe/SSL_read_ex")
int BPF_KPROBE(probe_ssl_read_ex_entry, void *ssl, void *buf, size_t num, size_t *readbytes) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr = (u64)buf;
    bpf_map_update_elem(&ssl_ctx_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
