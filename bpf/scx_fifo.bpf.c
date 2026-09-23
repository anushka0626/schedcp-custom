#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;

#define SHARED_DSQ_ID 0
#define FIFO_SLICE_NS 5000000ULL /* 5 ms slice */

extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

SEC("struct_ops.s/fifo_init")
s32 BPF_PROG(fifo_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

SEC("struct_ops/fifo_enqueue")
void BPF_PROG(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
    scx_bpf_dsq_insert(p, SHARED_DSQ_ID, FIFO_SLICE_NS, enq_flags);
}

SEC("struct_ops/fifo_dispatch")
void BPF_PROG(fifo_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
}

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
    .init           = (void *)fifo_init,
    .enqueue        = (void *)fifo_enqueue,
    .dispatch       = (void *)fifo_dispatch,
    .name           = "scx_fifo",
};

char _license[] SEC("license") = "GPL";