# SchedCP: Autonomous Kernel CPU Scheduler Hot-Swapping via eBPF & Model Context Protocol (MCP)

SchedCP is an agent-driven operating system control plane that dynamically hot-swaps Linux kernel CPU schedulers in Ring 0 without reboots or dropped tasks. By coupling **`sched-ext` (eBPF-extensible scheduling)** with an **MCP-compliant Rust control daemon** and an **autonomous profiling agent**, SchedCP continuously evaluates active workload hardware performance counters and deploys optimal scheduling topologies on the fly.

---

## Architecture Overview

```
                      +------------------------------------+
                      |    Autonomous Tuning Agent         |
                      |   (Python / LLM Reasoning Loop)    |
                      +-----------------+------------------+
                                        |
                                        | STDIO JSON-RPC 2.0 (MCP)
                                        v
                      +-----------------+------------------+
                      |       schedcp_daemon (Rust)        |
                      |  - Clang compiler driver           |
                      |  - BPF link lifecycle management   |
                      |  - sysfs kernel introspection      |
                      +-----------------+------------------+
                                        |
                                        | bpf() syscalls / bpftool
                                        v
  ============================ LINUX KERNEL (Ring 0) ============================
  +--------------------+   +----------------------------------------------------+
  |   Standard Linux   |   |                   sched-ext                        |
  |     Scheduler      |   |  +------------------------+  +-------------------+ |
  |      (EEVDF)       |<->|  | scx_fifo (Global DSQ)  |  | scx_batch2 (Local)| |
  |                    |   |  +------------------------+  +-------------------+ |
  +--------------------+   +----------------------------------------------------+

```

---

## What Has Been Done

### 1. Extensible eBPF Schedulers (`bpf/`)

Developed and verified custom scheduling policies written in restricted C using `vmlinux.h` BTF type definitions and `BPF_PROG` context unpacking macros:

* **`scx_fifo.bpf.c` (Centralized Work-Stealing FIFO):**
* Implements a single shared Dispatch Queue (`SHARED_DSQ_ID 0`) utilizing `scx_bpf_dsq_insert` and `scx_bpf_dsq_move_to_local`.
* Enforces a deterministic 5 ms slice to maximize core utilization across bursty workloads.


* **`scx_batch2.bpf.c` (Partitioned Core-Affinity Batch):**
* Dispatches directly to per-core hardware runqueues via `SCX_DSQ_LOCAL`.
* Configures an extended 30 ms uninterrupted time slice to suppress preemption churn and keep L1/L2 caches hot.



### 2. Rust MCP Control Daemon (`schedcp_daemon/`)

Built an asynchronous, memory-safe daemon acting as an MCP (Model Context Protocol) server over STDIO JSON-RPC 2.0:

* **Dynamic Toolchain Integration (`compile_scheduler`):** Invokes `clang -target bpf -O2` on demand with diagnostic capture.
* **Kernel Introspection (`get_scheduler_status`):** Inspects `/sys/kernel/sched_ext/state` and `/sys/kernel/sched_ext/root/ops` for active kernel state.
* **Safe Link Lifecycle Management (`load_scheduler` & `unload_scheduler`):** Idempotently manages `/sys/fs/bpf` pinned directories and detaches active `struct_ops` BPF links without deadlocks or resource-busy panics.

### 3. Profiling & Autonomous Feedback Loop (`autotune_agent.py` & `benchmark_runner.py`)

* Integrated `perf stat` hardware counters (`context-switches`, `cpu-migrations`, `task-clock`) alongside `sysbench` compute loads.
* Implemented heuristic-driven hypothesis generation that senses preemption thrashing and triggers MCP tool calls to swap kernel schedulers live.
* Verified execution metrics under live VM testing:
* **Context Switch Reduction:** -67.06%
* **Throughput Delta:** Up to +6.43% improvement over stock EEVDF.



---

## Directory Structure

```text
schedcp-project/
├── autotune_agent.py          # Autonomous closed-loop profiling & hot-swapper
├── benchmark_runner.py        # 3-way comparative performance harness
├── bpf/
│   ├── minimal.bpf.c          # Initial verification scheduler
│   ├── scx_batch2.bpf.c       # Partitioned core-affinity batch scheduler
│   ├── scx_fifo.bpf.c         # Centralized shared-queue FIFO scheduler
│   └── vmlinux.h              # In-kernel BTF type dump
└── schedcp_daemon/            # Rust MCP Server
    ├── Cargo.toml
    └── src/
        └── main.rs            # JSON-RPC parser & kernel controller implementation

```

---

## Prerequisites

* **Operating System:** Linux Kernel 6.12+ built with `CONFIG_BPF_JIT=y` and `CONFIG_SCHED_CLASS_EXT=y` (Tested on Fedora Linux 6.19.10).
* **System Packages:** `clang`, `llvm`, `libbpf`, `bpftool`, `sysbench`, `perf`.
* **Toolchains:** Rust (Cargo, rustc) & Python 3.8+.

---

## Quickstart

### 1. Build the Rust MCP Daemon

```bash
cd schedcp-project/schedcp_daemon
cargo build --release

```

### 2. Compile the eBPF Bytecode

```bash
cd ../bpf
clang -target bpf -g -O2 -c scx_fifo.bpf.c -o scx_fifo.bpf.o -I.
clang -target bpf -g -O2 -c scx_batch2.bpf.c -o scx_batch2.bpf.o -I.

```

### 3. Run the 3-Way Comparative Benchmark

```bash
cd ..
python3 benchmark_runner.py

```

### 4. Launch the Autonomous Autotune Loop

```bash
python3 autotune_agent.py

```

---

## What Will Be Done (Roadmap)

* [ ] **LLM Integration via MCP:** Replace static threshold heuristics in `autotune_agent.py` with an MCP-connected LLM client (Claude / Gemini / Ollama) that interprets raw hardware telemetry and issues MCP tool calls directly.
* [ ] **Dynamic Parameter Tuning:** Extend `compile_scheduler` to expose live tunable time slice intervals, core-pinning affinities, and priority weights generated on the fly.
* [ ] **Diverse Workload Benchmarking:** Expand evaluation beyond `sysbench cpu` to include:
* Cache-sensitive memory streaming loads.
* Multi-threaded kernel builds (`make -j$(nproc)`).
* High-concurrency I/O-bound web serving scenarios.


* [ ] **Self-Healing Kernel Watchdog Integration:** Hook into `sched-ext` failure exit dumps to automatically capture verifier or scheduling violation logs when user policies fail.