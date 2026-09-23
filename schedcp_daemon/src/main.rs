use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};  //Used for converting Rust structs ↔ JSON.
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::Command;

const SCHED_STATE_PATH: &str = "/sys/kernel/sched_ext/state";
const SCHED_OPS_PATH: &str = "/sys/kernel/sched_ext/root/ops";
const BPF_FS_DIR: &str = "/sys/fs/bpf";

// ==========================================
// 1. Kernel Scheduler Controller
// ==========================================

struct SchedulerController {
    struct_ops_name: String,
    pinned_link_path: String,
}

impl SchedulerController {
    fn new(struct_ops_name: &str) -> Self {
        Self {
            struct_ops_name: struct_ops_name.to_string(),
            pinned_link_path: format!("{}/{}", BPF_FS_DIR, struct_ops_name),
        }
    }

    fn is_active(&self) -> Result<bool> {
        if !Path::new(SCHED_STATE_PATH).exists() {
            bail!("sched-ext is not supported or enabled on this kernel");
        }
        let state = fs::read_to_string(SCHED_STATE_PATH)
            .context("Failed to read sched_ext state")?;
        Ok(state.trim() == "enabled")
    }

    fn current_ops_name(&self) -> Result<String> {
        if !self.is_active()? {
            return Ok("none (default EEVDF)".to_string());
        }
        let ops = fs::read_to_string(SCHED_OPS_PATH)
            .context("Failed to read active ops name")?;
        let trimmed = ops.trim();
        if trimmed.is_empty() {
            Ok("none (default EEVDF)".to_string())
        } else {
            Ok(trimmed.to_string())
        }
    }

    /// Compiles a C eBPF source file into .bpf.o using clang
    fn compile(&self, source_path: &str, output_path: &str, include_dir: &str) -> Result<String> {
        if !Path::new(source_path).exists() {
            bail!("Source file not found at: {}", source_path);
        }

        let output = Command::new("clang")
            .args([
                "-target", "bpf",
                "-g",
                "-O2",
                "-c", source_path,
                "-o", output_path,
                &format!("-I{}", include_dir),
            ])
            .output()
            .context("Failed to spawn clang process")?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            bail!("clang compilation failed:\n{}", stderr.trim());
        }

        Ok(format!(
            "Successfully compiled {} -> {}. Warnings/Info:\n{}",
            source_path,
            output_path,
            if stderr.trim().is_empty() { "None" } else { stderr.trim() }
        ))
    }

    fn load(&self, obj_path: &str) -> Result<String> {
        if self.is_active()? {
            bail!("A scheduler is already active. Unload it first.");
        }
        if !Path::new(obj_path).exists() {
            bail!("eBPF object file not found at: {}", obj_path);
        }

        // Force cleanup of any previous pins and links before registering
        let _ = Command::new("sudo").args(["rm", "-rf", &self.pinned_link_path]).output();
        let _ = self.detach_struct_ops_links();

        let output = Command::new("sudo")
            .args(["bpftool", "struct_ops", "register", obj_path, BPF_FS_DIR])
            .output()
            .context("Failed to execute bpftool register")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("bpftool register failed: {}", stderr.trim());
        }

        Ok(format!("Successfully loaded scheduler from {}", obj_path))
    }

    fn unload(&self) -> Result<String> {
        let _ = Command::new("sudo")
            .args(["rm", "-rf", &self.pinned_link_path])
            .output();

        self.detach_struct_ops_links()?;
        Ok("Scheduler unloaded. Kernel reverted to default EEVDF.".to_string())
    }

    // fn unload(&self) -> Result<String> {
    //     if Path::new(&self.pinned_link_path).exists() {
    //         let output = Command::new("sudo")
    //             .args(["rm", "-rf", &self.pinned_link_path])
    //             .output()
    //             .context("Failed to remove pinned link")?;

    //         if !output.status.success() {
    //             let stderr = String::from_utf8_lossy(&output.stderr);
    //             bail!("Failed to remove pinned link: {}", stderr.trim());
    //         }
    //     } else {
    //         self.detach_struct_ops_links()?;
    //     }
    //     Ok("Scheduler unloaded. Kernel reverted to default EEVDF.".to_string())
    // }

    fn detach_struct_ops_links(&self) -> Result<()> {
        let output = Command::new("sudo")
            .args(["bpftool", "link", "list"])
            .output()
            .context("Failed to query bpftool link list")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("struct_ops") {
                if let Some(id_part) = line.split(':').next() {
                    let link_id = id_part.trim();
                    let _ = Command::new("sudo")
                        .args(["bpftool", "link", "detach", "id", link_id])
                        .output();
                }
            }
        }
        Ok(())
    }
}

// ==========================================
// 2. JSON-RPC Protocol Structs
// ==========================================

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

// ==========================================
// 3. MCP Router & Request Handler
// ==========================================

fn handle_request(req: JsonRpcRequest, controller: &SchedulerController) -> Option<JsonRpcResponse> {
    let req_id = req.id.unwrap_or(Value::Null);

    let result = match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "schedcp-kernel-controller",
                "version": "0.1.0"
            },
            "capabilities": {
                "tools": {}
            }
        })),

        "notifications/initialized" => return None,

        "tools/list" => Ok(json!({
            "tools": [
                {
                    "name": "get_scheduler_status",
                    "description": "Returns whether a sched-ext scheduler is active and its name",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "compile_scheduler",
                    "description": "Compiles a C eBPF scheduler source file into bytecode (.bpf.o)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "source_path": {
                                "type": "string",
                                "description": "Absolute path to the C source file (.bpf.c)"
                            },
                            "output_path": {
                                "type": "string",
                                "description": "Absolute destination path for the compiled .bpf.o"
                            },
                            "include_dir": {
                                "type": "string",
                                "description": "Directory containing vmlinux.h and headers"
                            }
                        },
                        "required": ["source_path", "output_path", "include_dir"]
                    }
                },
                {
                    "name": "load_scheduler",
                    "description": "Loads a custom eBPF scheduler object file into the kernel",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute path to the compiled .bpf.o file"
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "unload_scheduler",
                    "description": "Detaches the active scheduler and reverts to default EEVDF",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }
            ]
        })),

        "tools/call" => {
            let tool_name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = req.params.get("arguments").cloned().unwrap_or(json!({}));

            match tool_name {
                "get_scheduler_status" => {
                    let active = controller.is_active().unwrap_or(false);
                    let name = controller.current_ops_name().unwrap_or_else(|e| e.to_string());
                    Ok(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": format!("sched-ext active: {}, running scheduler: {}", active, name)
                            }
                        ]
                    }))
                }
                "compile_scheduler" => {
                    let source = arguments.get("source_path").and_then(|v| v.as_str()).unwrap_or("");
                    let output = arguments.get("output_path").and_then(|v| v.as_str()).unwrap_or("");
                    let include = arguments.get("include_dir").and_then(|v| v.as_str()).unwrap_or("");

                    match controller.compile(source, output, include) {
                        Ok(msg) => Ok(json!({ "content": [{ "type": "text", "text": msg }] })),
                        Err(e) => Ok(json!({ "content": [{ "type": "text", "text": format!("Error: {:#}", e) }], "isError": true })),
                    }
                }
                "load_scheduler" => {
                    let path = arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    match controller.load(path) {
                        Ok(msg) => Ok(json!({ "content": [{ "type": "text", "text": msg }] })),
                        Err(e) => Ok(json!({ "content": [{ "type": "text", "text": format!("Error: {:#}", e) }], "isError": true })),
                    }
                }
                "unload_scheduler" => {
                    match controller.unload() {
                        Ok(msg) => Ok(json!({ "content": [{ "type": "text", "text": msg }] })),
                        Err(e) => Ok(json!({ "content": [{ "type": "text", "text": format!("Error: {:#}", e) }], "isError": true })),
                    }
                }
                _ => Err(json!({ "code": -32601, "message": format!("Unknown tool: {}", tool_name) })),
            }
        }

        _ => Err(json!({ "code": -32601, "message": format!("Method not found: {}", req.method) })),
    };

    let (res_val, err_val) = match result {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e)),
    };

    Some(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req_id,
        result: res_val,
        error: err_val,
    })
}

// ==========================================
// 4. Main Event Loop (STDIO Transport)
// ==========================================

fn main() -> Result<()> {
    let controller = SchedulerController::new("minimal_ops");
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(trimmed) {
            if let Some(resp) = handle_request(req, &controller) {
                let response_str = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", response_str)?;
                stdout.flush()?;
            }
        }
    }

    Ok(())
}