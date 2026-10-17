//! 设备身份与信任列表。
//!
//! 每台设备在首次运行时生成一对 Ed25519 密钥，公钥就是设备 ID。
//! 私钥只保存在本机，文件权限为仅本人可读写。
//! 信任列表记录允许连入本机的设备 ID，每台设备可以单独加入或移除。

use std::{
    collections::BTreeSet,
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use iroh::{EndpointId, SecretKey};

const SECRET_FILE: &str = "secret.key";
const TRUSTED_FILE: &str = "trusted";

/// 本机数据目录：优先使用环境变量 `MK_HOME`，否则为 `~/.config/mkconnect`。
pub fn default_home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("MK_HOME") {
        return Ok(dir.into());
    }
    let home =
        std::env::var_os("HOME").context("找不到 HOME 环境变量，请用 --home 指定数据目录")?;
    Ok(PathBuf::from(home).join(".config").join("mkconnect"))
}

/// 读取本机私钥；不存在时生成一把新的并保存。
pub fn load_or_create_secret(home: &Path) -> Result<SecretKey> {
    let path = home.join(SECRET_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            warn_if_readable_by_others(&path);
            let bytes = data_encoding::HEXLOWER
                .decode(text.trim().as_bytes())
                .with_context(|| format!("私钥文件格式错误：{}", path.display()))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("私钥长度应为 32 字节：{}", path.display()))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(home)
                .with_context(|| format!("无法创建数据目录：{}", home.display()))?;
            let secret = SecretKey::generate();
            let text = data_encoding::HEXLOWER.encode(&secret.to_bytes());
            write_private(&path, text.as_bytes())?;
            Ok(secret)
        }
        Err(err) => Err(err).with_context(|| format!("无法读取私钥：{}", path.display())),
    }
}

/// 允许连入本机的设备列表，保存为每行一个设备 ID 的文本文件。
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    ids: BTreeSet<String>,
}

impl TrustStore {
    pub fn load(home: &Path) -> Result<Self> {
        let path = home.join(TRUSTED_FILE);
        let ids = match fs::read_to_string(&path) {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(|line| {
                    let id: EndpointId = line
                        .parse()
                        .with_context(|| format!("信任列表中有无效的设备 ID：{line}"))?;
                    Ok(id.to_string())
                })
                .collect::<Result<_>>()?,
            Err(err) if err.kind() == ErrorKind::NotFound => BTreeSet::new(),
            Err(err) => {
                return Err(err).with_context(|| format!("无法读取信任列表：{}", path.display()));
            }
        };
        Ok(Self { path, ids })
    }

    pub fn contains(&self, id: &EndpointId) -> bool {
        self.ids.contains(&id.to_string())
    }

    pub fn ids(&self) -> Vec<EndpointId> {
        self.ids.iter().filter_map(|id| id.parse().ok()).collect()
    }

    /// 加入一台设备；已在列表中时返回 `false`。
    pub fn add(&mut self, id: EndpointId) -> Result<bool> {
        let added = self.ids.insert(id.to_string());
        if added {
            self.save()?;
        }
        Ok(added)
    }

    /// 移除一台设备；不在列表中时返回 `false`。
    pub fn remove(&mut self, id: &EndpointId) -> Result<bool> {
        let removed = self.ids.remove(&id.to_string());
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut text = String::from("# 允许连入本机的设备 ID，每行一个\n");
        for id in &self.ids {
            text.push_str(id);
            text.push('\n');
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("无法写入信任列表：{}", self.path.display()))
    }
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("无法创建私钥文件：{}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn warn_if_readable_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                "私钥文件 {} 可被其他用户读取，建议执行 chmod 600",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// 检查设备 ID 字符串是否有效，返回规范形式。
pub fn parse_endpoint_id(s: &str) -> Result<EndpointId> {
    match s.trim().parse() {
        Ok(id) => Ok(id),
        Err(_) => bail!("无效的设备 ID：{s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_secret(dir.path()).unwrap();
        let second = load_or_create_secret(dir.path()).unwrap();
        assert_eq!(first.public(), second.public());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(SECRET_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn trust_store_add_remove_persist() {
        let dir = tempfile::tempdir().unwrap();
        let id = SecretKey::generate().public();

        let mut store = TrustStore::load(dir.path()).unwrap();
        assert!(!store.contains(&id));
        assert!(store.add(id).unwrap());
        assert!(!store.add(id).unwrap());

        let mut reloaded = TrustStore::load(dir.path()).unwrap();
        assert!(reloaded.contains(&id));
        assert!(reloaded.remove(&id).unwrap());
        assert!(!TrustStore::load(dir.path()).unwrap().contains(&id));
    }
}
