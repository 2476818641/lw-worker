// 迷你 HTTP/1.1 客户端（零依赖，仅明文 http——直连 Controller 源站）。
// 目标体积：不做 TLS/重定向/分块等；响应体一次读入内存。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct Response {
    pub status: u16,
    pub body: String,
}

/// 发一次 POST JSON 请求，返回状态码与响应体。
pub fn post_json(host_port: &str, path: &str, token: &str, json: &str, timeout: Duration) -> Result<Response, HttpError> {
    request("POST", host_port, path, token, json, timeout)
}

/// 发一次 GET 请求。
pub fn get(host_port: &str, path: &str, token: &str, timeout: Duration) -> Result<Response, HttpError> {
    request("GET", host_port, path, token, "", timeout)
}

fn request(
    method: &str,
    host_port: &str,
    path: &str,
    token: &str,
    body: &str,
    timeout: Duration,
) -> Result<Response, HttpError> {
    let mut conn = TcpStream::connect(host_port)
        .map_err(|e| HttpError(format!("connect {host_port}: {e}")))?;
    conn.set_read_timeout(Some(timeout))
        .map_err(|e| HttpError(format!("set timeout: {e}")))?;
    conn.set_write_timeout(Some(timeout))
        .map_err(|e| HttpError(format!("set timeout: {e}")))?;

    let mut req = String::new();
    req.push_str(method);
    req.push(' ');
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\n");
    req.push_str("Host: ");
    req.push_str(host_port);
    req.push_str("\r\n");
    if !token.is_empty() {
        req.push_str("Authorization: Bearer ");
        req.push_str(token);
        req.push_str("\r\n");
    }
    req.push_str("User-Agent: blackout-lw/");
    req.push_str(env!("CARGO_PKG_VERSION"));
    req.push_str("\r\n");
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str("Content-Length: ");
        req.push_str(&body.len().to_string());
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    req.push_str(body);

    conn.write_all(req.as_bytes())
        .map_err(|e| HttpError(format!("write: {e}")))?;

    let mut buf = Vec::with_capacity(4096);
    conn.read_to_end(&mut buf)
        .map_err(|e| HttpError(format!("read: {e}")))?;
    parse_response(&buf)
}

fn parse_response(buf: &[u8]) -> Result<Response, HttpError> {
    // 头与体分离（\r\n\r\n）
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(HttpError("malformed response (no header end)".into()))?;

    let head = String::from_utf8_lossy(&buf[..head_end]);
    let mut lines = head.lines();
    let status_line = lines.next().ok_or(HttpError("empty response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError(format!("bad status line: {status_line}")))?;

    // Content-Length 解析（无则读到 EOF 已包含全部）
    let mut content_length: Option<usize> = None;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
    }
    let body = &buf[head_end + 4..];
    let body = match content_length {
        Some(n) => {
            let end = n.min(body.len());
            &body[..end]
        }
        None => body,
    };
    Ok(Response {
        status,
        body: String::from_utf8_lossy(body).into_owned(),
    })
}
