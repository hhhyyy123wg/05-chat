use std::{env, fs::File, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub port: u16,
}

impl AppConfig {
    pub fn load() -> Result<AppConfig> {
        let paths = vec![
            Some("./app.yml".to_string()),
            Some("/etc/config/app.yml".to_string()),
            env::var("CHAT_CONFIG").ok(),
        ];

        match paths.into_iter().flatten().find(|p| Path::new(p).exists()) {
            Some(path) => {
                let file =
                    File::open(&path).context(format!("Failed to open config file: {}", path))?;
                let config: AppConfig = serde_yaml::from_reader(file).map_err(|e| {
                    anyhow::Error::new(e).context(format!("Failed to parse config file: {}", path))
                })?;
                Ok(config)
            }
            None => bail!("No config file found"),
        }
    }
}
