use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: String,
    pub upstream: String,
    pub cert: String,
    pub key: String,
    pub path: String,
    pub socks_proxy: Option<SocksProxy>,
    /// 开启后,SOCKS5 服务端明确拒绝 UDP ASSOCIATE(回复码非 0,如 0x07/0x09)
    /// 时,该 UDP 会话回落为直连。注意隐私含义:回落会话不走代理、目标域名
    /// 由本地 DNS 解析、暴露本机真实出口 IP。缺省 false。
    #[serde(default)]
    pub socks_udp_fallback: bool,
    pub cwnd: Option<u64>,
}

/// SOCKS5 代理配置,格式为 `host:port` 或 `user:pass:host:port`(IPv6 需带方括号)。
/// 在反序列化时完成解析,格式错误直接 fail-fast,不会拖到运行时。
#[derive(Clone)]
pub struct SocksProxy {
    /// 可直接交给 `TcpStream::connect` 的 `host:port`(`[v6]:port` 保留方括号)。
    pub addr: String,
    /// 私有字段:避免 `{:?}` 打印整个 Config 时泄露密码。
    auth: Option<(String, String)>,
}

impl SocksProxy {
    pub fn auth(&self) -> Option<(&str, &str)> {
        self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
    }

    /// 从右往左剥:先取端口,再取 host,剩余部分按第一个冒号切成 `user:pass`
    /// (因此密码可以含冒号,用户名不行)。
    pub(crate) fn parse(s: &str) -> anyhow::Result<Self> {
        let (rest, port) = s
            .rsplit_once(':')
            .with_context(|| format!("invalid SOCKS5 proxy address (missing port): {s}"))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("invalid port in SOCKS5 proxy address: {s}"))?;
        // 无认证形态:`host:port`(剩余部分不含冒号)或 `[v6]:port`(以 [ 开头)。
        if rest.starts_with('[') || !rest.contains(':') {
            anyhow::ensure!(!rest.is_empty(), "empty host in SOCKS5 proxy address: {s}");
            return Ok(Self {
                addr: s.to_owned(),
                auth: None,
            });
        }
        // 认证形态:剩余部分是 creds:host。host 若以 ] 结尾则是方括号 IPv6,
        // 匹配回 `:[` 取整段;否则取最后一个冒号之后。
        let (creds, host) = if rest.ends_with(']') {
            let idx = rest
                .rfind(":[")
                .with_context(|| format!("invalid bracketed IPv6 in SOCKS5 proxy address: {s}"))?;
            (&rest[..idx], &rest[idx + 1..])
        } else {
            // 走到这里 rest 必然含冒号(上面已判定),unwrap 不会失败。
            rest.rsplit_once(':').unwrap()
        };
        anyhow::ensure!(!host.is_empty(), "empty host in SOCKS5 proxy address: {s}");
        let (user, pass) = creds
            .split_once(':')
            .with_context(|| format!("invalid credentials in SOCKS5 proxy address: {s}"))?;
        // RFC 1929:ULEN/PLEN 各 1 字节,凭据长度限制在 1-255 字节。
        anyhow::ensure!(
            !user.is_empty() && user.len() <= 255,
            "SOCKS5 username must be 1-255 bytes"
        );
        anyhow::ensure!(
            !pass.is_empty() && pass.len() <= 255,
            "SOCKS5 password must be 1-255 bytes"
        );
        Ok(Self {
            addr: format!("{host}:{port}"),
            auth: Some((user.to_owned(), pass.to_owned())),
        })
    }
}

/// 隐去密码,避免日志泄露。
impl std::fmt::Debug for SocksProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksProxy")
            .field("addr", &self.addr)
            .field("auth", &self.auth.as_ref().map(|(user, _)| (user, "***")))
            .finish()
    }
}

impl<'de> Deserialize<'de> for SocksProxy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

pub async fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = tokio::fs::read_to_string(path).await?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_host_port_without_auth() {
        let p = SocksProxy::parse("1.2.3.4:1080").unwrap();
        assert_eq!(p.addr, "1.2.3.4:1080");
        assert!(p.auth().is_none());
        let p = SocksProxy::parse("example.com:1080").unwrap();
        assert_eq!(p.addr, "example.com:1080");
        assert!(p.auth().is_none());
    }

    #[test]
    fn parses_bracketed_ipv6_without_auth() {
        let p = SocksProxy::parse("[::1]:1080").unwrap();
        assert_eq!(p.addr, "[::1]:1080");
        assert!(p.auth().is_none());
    }

    #[test]
    fn parses_auth_with_domain_and_ipv4() {
        let p = SocksProxy::parse("user:pass:example.com:1080").unwrap();
        assert_eq!(p.addr, "example.com:1080");
        assert_eq!(p.auth(), Some(("user", "pass")));
    }

    #[test]
    fn parses_auth_with_bracketed_ipv6() {
        let p = SocksProxy::parse("user:pass:[::1]:1080").unwrap();
        assert_eq!(p.addr, "[::1]:1080");
        assert_eq!(p.auth(), Some(("user", "pass")));
    }

    #[test]
    fn password_may_contain_colons() {
        let p = SocksProxy::parse("user:p:a:s:s:host:1080").unwrap();
        assert_eq!(p.addr, "host:1080");
        assert_eq!(p.auth(), Some(("user", "p:a:s:s")));
    }

    #[test]
    fn rejects_malformed_addresses() {
        // 缺端口、端口非数字、host 为空
        assert!(SocksProxy::parse("example.com").is_err());
        assert!(SocksProxy::parse("example.com:abc").is_err());
        assert!(SocksProxy::parse(":1080").is_err());
        // user 为空、pass 为空、creds 里没有冒号
        assert!(SocksProxy::parse(":pass:host:1080").is_err());
        assert!(SocksProxy::parse("user::host:1080").is_err());
        assert!(SocksProxy::parse("userpass:host:1080").is_err());
    }

    #[test]
    fn rejects_overlong_credentials() {
        let user = "u".repeat(256);
        assert!(SocksProxy::parse(format!("{user}:p:host:1080").as_str()).is_err());
        let pass = "p".repeat(256);
        assert!(SocksProxy::parse(format!("u:{pass}:host:1080").as_str()).is_err());
        // 255 字节是合法边界
        let user = "u".repeat(255);
        assert!(SocksProxy::parse(format!("{user}:p:host:1080").as_str()).is_ok());
    }

    #[test]
    fn debug_hides_password() {
        let p = SocksProxy::parse("user:secret:host:1080").unwrap();
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("***"));
    }

    #[test]
    fn toml_deserialization_fails_fast_on_bad_proxy() {
        let bad = r#"
            listen = "127.0.0.1:443"
            upstream = "http://127.0.0.1:80"
            cert = "c.pem"
            key = "k.pem"
            path = "/"
            socks_proxy = "user:pass:noport"
        "#;
        assert!(toml::from_str::<Config>(bad).is_err());
    }

    #[test]
    fn udp_fallback_defaults_to_false() {
        let minimal = r#"
            listen = "127.0.0.1:443"
            upstream = "http://127.0.0.1:80"
            cert = "c.pem"
            key = "k.pem"
            path = "/"
        "#;
        assert!(
            !toml::from_str::<Config>(minimal)
                .unwrap()
                .socks_udp_fallback
        );
    }

    #[test]
    fn udp_fallback_parses_true() {
        let with_flag = r#"
            listen = "127.0.0.1:443"
            upstream = "http://127.0.0.1:80"
            cert = "c.pem"
            key = "k.pem"
            path = "/"
            socks_udp_fallback = true
        "#;
        assert!(
            toml::from_str::<Config>(with_flag)
                .unwrap()
                .socks_udp_fallback
        );
    }
}
