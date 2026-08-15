// 伪源 UDP 发包核心：raw socket + IP_HDRINCL，构造完整 IPv4+UDP 头。
// 仅支持 IPv4。目标平台为 Linux（路由器/OpenWrt）；Windows 上编译为 stub
// （raw socket 语义不同，且非部署目标）。

use std::io;

#[derive(Debug)]
pub struct SpoofError(pub String);

impl std::fmt::Display for SpoofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(unix)]
pub use imp_unix::{self_check, SpoofSocket};

#[cfg(not(unix))]
pub use imp_stub::{self_check, SpoofSocket};

#[cfg(unix)]
mod imp_unix {
    use super::*;

    pub struct SpoofSocket {
        fd: i32,
    }

    /// 自检：能否创建 raw socket（需 root + 内核允许）。失败返回 Err。
    pub fn self_check() -> Result<(), SpoofError> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(SpoofError(format!(
                "raw socket failed: {} (need root?)",
                io::Error::last_os_error()
            )));
        }
        unsafe { libc::close(fd) };
        Ok(())
    }

    impl SpoofSocket {
        pub fn new() -> Result<Self, SpoofError> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
            if fd < 0 {
                return Err(SpoofError(format!(
                    "raw socket failed: {} (need root?)",
                    io::Error::last_os_error()
                )));
            }
            // IP_HDRINCL：由我们构造完整 IP 头
            let one: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            Ok(SpoofSocket { fd })
        }

        /// 发送一个伪源 UDP 包：src_ip → dst_ip:dst_port，payload 为 UDP 数据。
        pub fn send_udp(&self, src_ip: [u8; 4], dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> io::Result<usize> {
            let udp_len = 8 + payload.len();
            let total_len = 20 + udp_len;
            let mut pkt = vec![0u8; total_len];

            // IPv4 头
            pkt[0] = 0x45; // version 4, IHL 5
            pkt[1] = 0x00;
            pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            pkt[8] = 64; // TTL
            pkt[9] = 17; // UDP
            pkt[12..16].copy_from_slice(&src_ip);
            pkt[16..20].copy_from_slice(&dst_ip);
            let ip_csum = checksum(&pkt[..20]);
            pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            // UDP 头（校验和填 0：IPv4 可选；反射器场景不校验源端口）
            pkt[20..22].copy_from_slice(&0u16.to_be_bytes());
            pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
            pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
            pkt[26..28].copy_from_slice(&0u16.to_be_bytes());
            pkt[28..].copy_from_slice(payload);

            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: dst_port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dst_ip),
                },
                sin_zero: [0; 8],
            };

            let n = unsafe {
                libc::sendto(
                    self.fd,
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Drop for SpoofSocket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Windows 占位实现：raw socket 语义不同且非部署目标。
/// 编译可过；运行时 self_check 直接失败（节点被丢弃）。
#[cfg(not(unix))]
mod imp_stub {
    use super::*;

    pub struct SpoofSocket;

    pub fn self_check() -> Result<(), SpoofError> {
        Err(SpoofError("raw socket not supported on this platform (Linux only)".into()))
    }

    impl SpoofSocket {
        pub fn new() -> Result<Self, SpoofError> {
            Err(SpoofError("raw socket not supported on this platform (Linux only)".into()))
        }

        pub fn send_udp(&self, _src_ip: [u8; 4], _dst_ip: [u8; 4], _dst_port: u16, _payload: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "raw socket not supported on this platform"))
        }
    }
}

/// IPv4 头校验和
#[cfg(unix)]
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 字符串 IP → 4 字节（简化解析，失败返回 None）
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

/// 4 字节 IP → 字符串
pub fn fmt_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
