mod cluster;
mod command_catalog;
mod config;
mod protocol;
mod response;
mod server;
mod telemetry;
mod tenant;
mod upstream;

use anyhow::Result;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "rproxy=info".to_owned()))
        .with_target(false)
        .init();

    let config_path = config_path()?;
    server::run(config::load(&config_path)?).await
}

fn config_path() -> Result<PathBuf> {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next() {
        None => Ok(PathBuf::from("rproxy.toml")),
        Some(flag) if flag == "--config" => arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("--config requires a path")),
        Some(flag) => Err(anyhow::anyhow!(
            "unknown argument {:?}; use --config <path>",
            flag
        )),
    }
}
