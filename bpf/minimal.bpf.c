#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SHARED_DSQ_ID 0  //dsq: dispatch queue
//sched_ext uses dispatch queues as an important mechanism for moving runnable tasks toward CPUs


//Forward declarations of sched-ext kernel kfuncs
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

//Lifecycle callback: runs when the scheduler attaches.
SEC("struct_ops.s/min_init")
s32 BPF_PROG(min_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

//Task enqueue: BPF_PROG unpacks context registers cleanly for the verifier.
SEC("struct_ops/min_enqueue")
void BPF_PROG(min_enqueue, struct task_struct *p, u64 enq_flags)
{
    scx_bpf_dsq_insert(p, SHARED_DSQ_ID, 5000000, enq_flags);
}

/*
 * Task dispatch: core pulls work from the shared queue.
 */
SEC("struct_ops/min_dispatch")
void BPF_PROG(min_dispatch, s32 cpu, struct task_struct *prev){
    scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
}

/*
 * sched_ext operations table
 */
SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
    .init           = (void *)min_init,
    .enqueue        = (void *)min_enqueue,
    .dispatch       = (void *)min_dispatch,
    .name           = "scx_minimal",
};

char _license[] SEC("license") = "GPL";