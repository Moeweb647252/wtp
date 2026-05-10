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
}

pub async fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = tokio::fs::read_to_string(path).await?;
    let config = toml::from_str(&content)?;
    Ok(config)
}
