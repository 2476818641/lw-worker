// 节流：目标 PPS 上限（令牌桶简化版），
// 可选负载自适应：/proc/loadavg 超过阈值时自动降速（路由器 CPU 保护）。

use std::time::Instant;

pub struct Throttle {
    max_pps: u64,
    tokens: f64,
    last: Instant,
    rate: f64, // 当前速率倍数（1.0 / 0.5）
}

impl Throttle {
    pub fn new(max_pps: u64) -> Self {
        Throttle {
            max_pps,
            tokens: max_pps as f64,
            last: Instant::now(),
            rate: 1.0,
        }
    }

    /// 有令牌则消费并返回 true；否则 false（调用方应短暂 sleep）
    pub fn allow(&mut self) -> bool {
        if self.max_pps == 0 {
            return true; // 不限速
        }
        // 负载自适应：loadavg(1min) 超过 CPU 数 → 半速
        self.adapt();

        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let cap = (self.max_pps as f64) * self.rate;
        self.tokens = (self.tokens + elapsed * cap).min(cap);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn adapt(&mut self) {
        if let Some(load) = read_loadavg_1min() {
            let cpus = num_cpus() as f64;
            if load > cpus * 1.5 {
                self.rate = 0.5;
            } else {
                self.rate = 1.0;
            }
        }
    }
}

fn read_loadavg_1min() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    let first = s.split_whitespace().next()?;
    first.parse().ok()
}

fn num_cpus() -> u32 {
    // 简化：扫描 /sys/devices/system/cpu/ 下的 cpu 目录
    std::fs::read_dir("/sys/devices/system/cpu")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("cpu") && e.file_name().to_string_lossy().len() > 3)
                .count() as u32
        })
        .unwrap_or(1)
        .max(1)
}
