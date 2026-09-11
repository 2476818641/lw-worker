// 迷你 HTTP/1.1 客户端（零依赖，仅明文 http——直连 Controller 源站）。
// 支持 Content-Length 与 Transfer-Encoding: chunked（Controller 的
// json.Encoder 在响应超过 2KB 缓冲阈值时自动转 chunked——反射器池
// 列表必然超过，不支持 chunked 会导致池永远拉取失败、攻击空转）。

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

    // Content-Length / Transfer-Encoding 解析
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
        if let Some(v) = lower.strip_prefix("transfer-encoding:") {
            if v.contains("chunked") {
                chunked = true;
            }
        }
    }
    let raw = &buf[head_end + 4..];
    let body: Vec<u8> = if chunked {
        decode_chunked(raw)?
    } else {
        match content_length {
            Some(n) => raw[..n.min(raw.len())].to_vec(),
            None => raw.to_vec(),
        }
    };
    Ok(Response {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// 解码 HTTP/1.1 chunked 响应体：`<hex size>[;ext]\r\n<data>\r\n ... 0\r\n\r\n`
fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let nl = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(HttpError("malformed chunked body (no size line)".into()))?;
        let size_line = String::from_utf8_lossy(&data[..nl]);
        // 允许 chunk 扩展（`size;ext=val`）
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| HttpError(format!("bad chunk size: {size_str:?}")))?;
        data = &data[nl + 2..];
        if size == 0 {
            break; // 结束块（尾部 trailers 忽略：Connection: close 场景无影响）
        }
        if data.len() < size {
            return Err(HttpError(format!(
                "truncated chunk: need {size} bytes, have {}",
                data.len()
            )));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.len() >= 2 && &data[..2] == b"\r\n" {
            data = &data[2..];
        }
    }
    Ok(out)
}
