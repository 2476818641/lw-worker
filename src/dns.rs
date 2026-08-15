// DNS 查询构造：随机 ID + 指定域名 + TXT 查询（放大用，响应大）。
// 请求最小化：5B 头 + 域名编码 + 4B 尾部 = 约 20-40B。

/// 构造一个 DNS TXT 查询包
pub fn build_txt_query(domain: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    // 头：ID + flags(0x0100 RD) + QDCOUNT=1
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // QNAME（label 编码）
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        let b = label.as_bytes();
        if b.len() > 63 {
            continue;
        }
        q.push(b.len() as u8);
        q.extend_from_slice(b);
    }
    q.push(0);
    // QTYPE=TXT(16), QCLASS=IN(1)
    q.extend_from_slice(&16u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_txt_query() {
        let q = build_txt_query("isc.org", 0x1234);
        assert!(q.len() > 20);
        assert_eq!(&q[..2], &0x1234u16.to_be_bytes());
        // QDCOUNT=1
        assert_eq!(&q[4..6], &1u16.to_be_bytes());
        // 域名 label 编码
        assert_eq!(q[12], 3); // "isc"
        assert_eq!(&q[13..16], b"isc");
        assert_eq!(q[16], 3); // "org"
        assert_eq!(&q[17..20], b"org");
        assert_eq!(q[20], 0); // root
        // TXT + IN
        assert_eq!(&q[21..23], &16u16.to_be_bytes());
        assert_eq!(&q[23..25], &1u16.to_be_bytes());
    }
}
