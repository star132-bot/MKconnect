//! 连接票据：把设备 ID、直连地址和中继地址打包成一段可复制的文本。
//!
//! 票据以 `mk1` 开头，后面是 base32 编码的地址信息。
//! 连接时也可以只给设备 ID，此时依靠地址发现服务查找对方。

use std::net::SocketAddr;

use anyhow::{Context, Result};
use data_encoding::BASE32_NOPAD;
use iroh::{EndpointAddr, EndpointId, TransportAddr};

const PREFIX: &str = "mk1";

/// 把端点地址编码为票据文本。
pub fn encode(addr: &EndpointAddr) -> String {
    let bytes = postcard::to_stdvec(addr).expect("端点地址总能序列化");
    format!(
        "{PREFIX}{}",
        BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
    )
}

/// 解析票据文本。
pub fn decode(ticket: &str) -> Result<EndpointAddr> {
    let body = ticket
        .trim()
        .strip_prefix(PREFIX)
        .context("票据应以 mk1 开头")?;
    let bytes = BASE32_NOPAD
        .decode(body.to_ascii_uppercase().as_bytes())
        .context("票据编码错误")?;
    postcard::from_bytes(&bytes).context("票据内容无法解析")
}

/// 解析连接目标，支持三种写法：
/// - 票据：`mk1...`
/// - 设备 ID：依靠地址发现服务查找对方
/// - `设备ID@地址:端口`：直接指定对方地址，可用逗号写多个
pub fn parse_target(target: &str) -> Result<EndpointAddr> {
    let target = target.trim();
    if target.starts_with(PREFIX) {
        return decode(target);
    }
    let (id, addrs) = match target.split_once('@') {
        Some((id, addrs)) => (id, Some(addrs)),
        None => (target, None),
    };
    let id: EndpointId = id
        .parse()
        .with_context(|| format!("既不是票据也不是设备 ID：{target}"))?;
    let Some(addrs) = addrs else {
        return Ok(EndpointAddr::from(id));
    };
    let addrs = addrs
        .split(',')
        .map(|a| {
            a.trim()
                .parse::<SocketAddr>()
                .map(TransportAddr::Ip)
                .with_context(|| format!("地址格式应为 IP:端口：{a}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(EndpointAddr::from_parts(id, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn roundtrip_with_addresses() {
        let id = SecretKey::generate().public();
        let addr = EndpointAddr::from_parts(
            id,
            [
                TransportAddr::Ip("192.168.1.20:4433".parse().unwrap()),
                TransportAddr::Ip("[2001:db8::1]:4433".parse().unwrap()),
            ],
        );
        let ticket = encode(&addr);
        assert!(ticket.starts_with("mk1"));
        assert_eq!(decode(&ticket).unwrap(), addr);
        assert_eq!(parse_target(&ticket).unwrap(), addr);
    }

    #[test]
    fn bare_endpoint_id_is_accepted() {
        let id = SecretKey::generate().public();
        let addr = parse_target(&id.to_string()).unwrap();
        assert_eq!(addr.id, id);
    }

    #[test]
    fn id_with_explicit_addresses() {
        let id = SecretKey::generate().public();
        let addr = parse_target(&format!("{id}@127.0.0.1:4000,[::1]:4000")).unwrap();
        assert_eq!(addr.id, id);
        assert_eq!(addr.ip_addrs().count(), 2);
        assert!(parse_target(&format!("{id}@not-an-addr")).is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_target("mk1!!!").is_err());
        assert!(parse_target("hello").is_err());
    }
}
