//! 网络端点：按配置创建 iroh 端点，决定用哪些中继、是否允许直连。

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey, endpoint::presets, tls::CaTlsConfig,
};
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::proto::ALPN;

/// 使用哪些中继服务器。
#[derive(Debug, Clone, Default)]
pub enum RelayChoice {
    /// iroh 官方公共中继与地址发现服务，仅适合开发测试。
    #[default]
    Public,
    /// 自建中继，可以写多个，自动选延迟最低的。
    Custom(Vec<RelayUrl>),
    /// 不使用任何中继，只能直连。
    Disabled,
}

#[derive(Debug, Clone, Default)]
pub struct NetOptions {
    pub relay: RelayChoice,
    /// 自建中继使用自签名证书时，信任这个 PEM 文件里的证书。
    pub relay_ca: Option<PathBuf>,
    /// 只走中继、禁止直连，用于测试中继兜底。
    pub relay_only: bool,
    /// 固定本地 UDP 端口，便于防火墙放行；不填则随机。
    pub port: Option<u16>,
}

/// 创建并启动网络端点。
pub async fn bind(secret: SecretKey, opts: &NetOptions) -> Result<Endpoint> {
    if opts.relay_only && matches!(opts.relay, RelayChoice::Disabled) {
        bail!("“只走中继”和“不用中继”不能同时开启");
    }

    let mut builder = match opts.relay {
        RelayChoice::Public => Endpoint::builder(presets::N0),
        _ => Endpoint::builder(presets::Minimal),
    };
    builder = builder.secret_key(secret).alpns(vec![ALPN.to_vec()]);

    match &opts.relay {
        RelayChoice::Public => {}
        RelayChoice::Custom(urls) => {
            if urls.is_empty() {
                bail!("至少需要一个中继地址");
            }
            builder = builder.relay_mode(RelayMode::Custom(RelayMap::from_iter(urls.clone())));
        }
        RelayChoice::Disabled => builder = builder.relay_mode(RelayMode::Disabled),
    }

    if let Some(path) = &opts.relay_ca {
        let certs = CertificateDer::pem_file_iter(path)
            .with_context(|| format!("无法读取中继证书：{}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("中继证书格式错误：{}", path.display()))?;
        if certs.is_empty() {
            bail!("中继证书文件里没有证书：{}", path.display());
        }
        builder = builder.ca_tls_config(CaTlsConfig::custom_roots(certs));
    }

    if opts.relay_only {
        builder = builder.clear_ip_transports();
    } else if let Some(port) = opts.port {
        builder = builder
            .bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .context("无法绑定指定端口")?;
    }

    let endpoint = builder.bind().await.context("无法启动网络端点")?;

    if !matches!(opts.relay, RelayChoice::Disabled) {
        // 等待连上中继，超时也继续：直连仍可能成功。
        let online = tokio::time::timeout(Duration::from_secs(5), endpoint.online()).await;
        if online.is_err() {
            tracing::warn!("5 秒内未连上中继，将只尝试直连");
        }
    }
    Ok(endpoint)
}
