// 反射器池：从 Controller 拉取 + 内存缓存。
// 池条目格式（与 Controller /api/reflectors/all 对齐）："ip:port|amp_domain"

use crate::http;
use crate::spoof::parse_ipv4;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Reflector {
    pub ip: [u8; 4],
    pub port: u16,
    pub domain: String, // 空 = 用默认放大域
}

pub fn parse_entry(s: &str) -> Option<Reflector> {
    let (addr, domain) = match s.rsplit_once('|') {
        Some((a, d)) => (a, d.to_string()),
        None => (s, String::new()),
    };
    let (ip_str, port_str) = addr.rsplit_once(':')?;
    let ip = parse_ipv4(ip_str)?;
    let port: u16 = port_str.parse().ok()?;
    Some(Reflector { ip, port, domain })
}

/// 拉取 DNS 反射器池
pub fn fetch_dns_pool(host_port: &str, token: &str, limit: usize) -> Result<Vec<Reflector>, http::HttpError> {
    let path = format!("/api/reflectors/all?pool=dns&limit={limit}");
    let resp = http::get(host_port, &path, token, Duration::from_secs(20))?;
    if resp.status != 200 {
        return Err(http::HttpError(format!("pool fetch http {}", resp.status)));
    }
    // 响应是 JSON 字符串数组 ["ip:port|domain", ...]
    let items: Vec<String> = serde_json::from_str(&resp.body)
        .map_err(|e| http::HttpError(format!("pool parse: {e}")))?;
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if let Some(r) = parse_entry(&it) {
            out.push(r);
        }
    }
    Ok(out)
}
