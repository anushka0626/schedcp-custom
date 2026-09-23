//a batch scheduler is a cpu scheduling design.
//a batch scheduler groups tasks and gives them long, uninterrupted chunks of CPU 
//time to process work as efficiently as possible

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SHARED_DSQ_ID 0  //dsq: dispatch queue
//sched_ext uses dispatch queues as an important mechanism for moving runnable tasks toward CPUs


//Forward declarations of sched-ext kernel kfuncs
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

//initialise the scheduler
SEC("struct_ops.s/min_init")
s32 BPF_PROG(min_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}


/* this is how it is declared: void (*enqueue)(struct task_struct *p, u64 enq_flags);
@p task that bhas become runnable and needs to be scheduled
@enq_flags: these flags describe how/why the task is being enqueued.
When a task becomes runnable, sched_ext calls this function so that
 * the BPF scheduler can decide where to put the task.
 *
 * The task should normally be inserted into a dispatch queue (DSQ)
 * using scx_bpf_dsq_insert(). Once the BPF scheduler takes ownership
 * of the task, it is responsible for eventually dispatching it to a CPU.
 *
 * In this scheduler, every runnable task is inserted into one shared
 * DSQ. The dispatch callback later moves a task from this shared DSQ
 * to the local DSQ of a CPU.
 *
 * If a task was already inserted into a DSQ by select_cpu(), enqueue()
 * is skipped for that task.

*/
//Task enqueue: BPF_PROG unpacks context registers cleanly for the verifier.
SEC("struct_ops/min_enqueue")
void BPF_PROG(min_enqueue, struct task_struct *p, u64 enq_flags)
{
    scx_bpf_dsq_insert(p, SHARED_DSQ_ID, 20000000, enq_flags);
}


/*this is how it is declared: void (*dispatch)(s32 cpu, struct task_struct *prev);
@cpu means the cpu to dispatch the task to
@prev indicates the the task that was running until now and now will be switched out
So all in all the declaration here:
SEC("struct_ops/min_dispatch") means that this func moves a task from the shared dsq
into the local dsq of the target cpu
*/
//Task dispatch: core pulls work from the shared queue.
SEC("struct_ops/min_dispatch")
void BPF_PROG(min_dispatch, s32 cpu, struct task_struct *prev){
    scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
}

//sched_ext operations table [declaratiions vs names given here]

SEC(".struct_ops.link")
struct sched_ext_ops minimal_ops = {
    .init           = (void *)min_init,
    .enqueue        = (void *)min_enqueue,
    .dispatch       = (void *)min_dispatch,
    .name           = "scx_batch",
};

char _license[] SEC("license") = "GPL";
