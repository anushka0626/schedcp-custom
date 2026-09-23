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
        self._init_handshake()

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

    def _init_handshake(self):
        self._call("initialize")

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

def run_probe_workload(threads=4, time_sec=5):
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

class AutotuneAgent:
    def __init__(self, mcp_client):
        self.client = mcp_client

    def profile_and_decide(self, baseline_metrics):
        print("\n[Agent Thinking Process]")
        print(f"  * Baseline Events/sec : {baseline_metrics['eps']}")
        print(f"  * Baseline Ctx Switches: {baseline_metrics['context_switches']}")
        print(f"  * Baseline Migrations : {baseline_metrics['cpu_migrations']}")

        # Systems decision:
        # High preemption churn benefits from the partitioned batch queue with larger 30ms slice
        if baseline_metrics['context_switches'] > 3000:
            hypothesis = (
                "Workload suffers from heavy context switching under EEVDF. "
                "Recommendation: Deploy 'scx_batch2' (Partitioned Local Queues, 30ms slice) "
                "to pin threads to cores and suppress preemption overhead."
            )
            selected_scheduler = BATCH_OBJ
            target_name = "scx_batch2"
        else:
            hypothesis = (
                "Workload preemption is low. "
                "Recommendation: Deploy 'scx_fifo' (Global Work-Stealing) to maximize idle core utilization."
            )
            selected_scheduler = FIFO_OBJ
            target_name = "scx_fifo"

        print(f"  -> Hypothesis: {hypothesis}")
        return selected_scheduler, target_name

    def optimize_loop(self):
        print("==================================================")
        print("       SchedCP Autonomous Tuning Loop Starting    ")
        print("==================================================")

        # 1. Clean environment
        subprocess.run(["sudo", "rm", "-rf", "/sys/fs/bpf/minimal_ops"], capture_output=True)
        self.client.unload_scheduler()

        print("\n[Phase 1] Profiling baseline workload under default Linux (EEVDF)...")
        baseline = run_probe_workload()

        # 2. Agent reasoning
        scheduler_path, target_name = self.profile_and_decide(baseline)

        # 3. Apply via MCP
        print(f"\n[Phase 2] Agent applying optimization: Loading {target_name} via MCP...")
        load_res = self.client.load_scheduler(scheduler_path)
        print(f"  Server response: {load_res}")
        print(f"  Active Status: {self.client.get_status()}")

        # 4. Measure optimized
        print(f"\n[Phase 3] Profiling workload under {target_name}...")
        optimized = run_probe_workload()

        # 5. Clean up
        print("\n[Phase 4] Reverting system back to default EEVDF...")
        self.client.unload_scheduler()
        print(f"  Active Status: {self.client.get_status()}")

        # 6. Evaluation
        eps_gain = ((optimized['eps'] - baseline['eps']) / baseline['eps']) * 100
        ctx_delta = ((optimized['context_switches'] - baseline['context_switches']) / baseline['context_switches']) * 100
        mig_delta = optimized['cpu_migrations'] - baseline['cpu_migrations']

        print("\n==================================================")
        print("               Autotune Results                   ")
        print("==================================================")
        print(f"Throughput Delta       : {eps_gain:+.2f}%")
        print(f"Context Switch Delta   : {ctx_delta:+.2f}%")
        print(f"CPU Migration Shift    : {mig_delta:+d}")
        print(f"Selected Policy        : {target_name}")
        
        if eps_gain >= 0 or ctx_delta < 0:
            print("Verdict                : OPTIMIZATION SUCCESSFUL")
        else:
            print("Verdict                : WORKLOAD PREFERS DEFAULT KERNEL")
        print("==================================================")

def main():
    client = McpClient(DAEMON_PATH)
    agent = AutotuneAgent(client)
    try:
        agent.optimize_loop()
    finally:
        client.close()

if __name__ == "__main__":
    main()