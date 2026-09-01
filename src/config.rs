use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: String,
    pub upstream: String,
    pub cert: String,
    pub key: String,
    pub path: String,
    pub socks_proxy: Option<String>,
    pub cwnd: Option<u64>,
    #[serde(default = "default_max_webtransport_sessions")]
    pub max_webtransport_sessions: u64,
}

fn default_max_webtransport_sessions() -> u64 {
    1
}

pub async fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = tokio::fs::read_to_string(path).await?;
    let config: Config = toml::from_str(&content)?;
    anyhow::ensure!(
        config.max_webtransport_sessions >= 1,
        "max_webtransport_sessions must be at least 1"
    );
    Ok(config)
}
