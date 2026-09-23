''' this python script is a benchmark runner for the schedcp project. 
It communicates with the schedcp_daemon via JSON-RPC over STDIO, 
runs sysbench workloads under perf stat, and collects performance metrics for comparison between 
the default EEVDF scheduler and the custom eBPF scheduler (scx_minimal). 
The script provides a summary of events per second, context switches, CPU migrations, and average latency for both schedulers. '''

#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time

PROJECT_DIR = os.path.expanduser("~/schedcp-project")
DAEMON_PATH = os.path.join(PROJECT_DIR, "schedcp_daemon/target/release/schedcp_daemon")
FIFO_OBJ = os.path.join(PROJECT_DIR, "bpf/scx_fifo.bpf.o")
BATCH_OBJ = os.path.join(PROJECT_DIR, "bpf/scx_batch2.bpf.o")

class McpClient:
    def __init__(self, daemon_path):
        self.proc = subprocess.Popen(
            [daemon_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        self.msg_id = 0
        self._call("initialize")

    def _call(self, method, params=None):
        self.msg_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self.msg_id,
            "method": method,
            "params": params or {}
        }
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line.strip())

    def get_status(self):
        res = self._call("tools/call", {"name": "get_scheduler_status", "arguments": {}})
        return res["result"]["content"][0]["text"]

    def load_scheduler(self, path):
        res = self._call("tools/call", {"name": "load_scheduler", "arguments": {"path": path}})
        return res["result"]["content"][0]["text"]

    def unload_scheduler(self):
        res = self._call("tools/call", {"name": "unload_scheduler", "arguments": {}})
        return res["result"]["content"][0]["text"]

    def close(self):
        self.proc.stdin.close()
        self.proc.terminate()
        self.proc.wait()

def run_workload(threads=4, time_sec=10):
    cmd = [
        "sudo", "perf", "stat",
        "-e", "task-clock,context-switches,cpu-migrations",
        "sysbench", "cpu",
        "--cpu-max-prime=20000",
        f"--threads={threads}",
        f"--time={time_sec}",
        "run"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    combined = res.stdout + res.stderr

    events_per_sec = re.search(r"events per second:\s+([\d\.]+)", combined)
    avg_latency = re.search(r"avg:\s+([\d\.]+)", combined)
    ctx_switches = re.search(r"([\d,]+)\s+context-switches", combined)
    cpu_migrations = re.search(r"([\d,]+)\s+cpu-migrations", combined)

    return {
        "eps": float(events_per_sec.group(1)) if events_per_sec else 0.0,
        "avg_lat_ms": float(avg_latency.group(1)) if avg_latency else 0.0,
        "context_switches": int(ctx_switches.group(1).replace(",", "")) if ctx_switches else 0,
        "cpu_migrations": int(cpu_migrations.group(1).replace(",", "")) if cpu_migrations else 0,
    }

def main():
    print("=== SchedCP 3-Way Architectural Benchmark ===")
    client = McpClient(DAEMON_PATH)

    # 1. Baseline Run (EEVDF)
    print("\n[1/3] Ensuring baseline (EEVDF)...")
    client.unload_scheduler()
    print(f"      Status: {client.get_status()}")
    eevdf_stats = run_workload()
    time.sleep(1)

    # 2. Global Shared FIFO (scx_fifo)
    print("\n[2/3] Loading scx_fifo (Global Work-Stealing FIFO)...")
    load_msg = client.load_scheduler(FIFO_OBJ)
    print(f"      Daemon: {load_msg}")
    print(f"      Status: {client.get_status()}")
    fifo_stats = run_workload()
    client.unload_scheduler()
    time.sleep(1)

    # 3. Partitioned Local Batch (scx_batch2)
    print("\n[3/3] Loading scx_batch2 (Partitioned Core-Affinity Batch)...")
    load_msg = client.load_scheduler(BATCH_OBJ)
    print(f"      Daemon: {load_msg}")
    print(f"      Status: {client.get_status()}")
    batch_stats = run_workload()
    client.unload_scheduler()
    print(f"      Status: {client.get_status()}")
    client.close()

    # Results Table
    print("\n" + "=" * 70)
    print(f"{'Metric':<20} | {'EEVDF':<13} | {'scx_fifo':<13} | {'scx_batch2':<13}")
    print("-" * 70)
    print(f"{'Events / sec':<20} | {eevdf_stats['eps']:<13.2f} | {fifo_stats['eps']:<13.2f} | {batch_stats['eps']:<13.2f}")
    print(f"{'Context Switches':<20} | {eevdf_stats['context_switches']:<13} | {fifo_stats['context_switches']:<13} | {batch_stats['context_switches']:<13}")
    print(f"{'CPU Migrations':<20} | {eevdf_stats['cpu_migrations']:<13} | {fifo_stats['cpu_migrations']:<13} | {batch_stats['cpu_migrations']:<13}")
    print(f"{'Avg Latency (ms)':<20} | {eevdf_stats['avg_lat_ms']:<13.2f} | {fifo_stats['avg_lat_ms']:<13.2f} | {batch_stats['avg_lat_ms']:<13.2f}")
    print("=" * 70)

if __name__ == "__main__":
    main()