//this is more batch like instead of the first file
// 

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;

#define BATCH_SLICE_NS 30000000ULL /* 30 ms slice */

extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;

SEC("struct_ops/batch_enqueue")
void BPF_PROG(batch_enqueue, struct task_struct *p, u64 enq_flags)
{
    /* Direct insert to the CPU's local hardware runqueue */
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, BATCH_SLICE_NS, enq_flags);
}

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
    .enqueue        = (void *)batch_enqueue,
    .name           = "scx_batch",
};

char _license[] SEC("license") = "GPL";