use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{collections::HashSet, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub schema_version: u16,
    pub listener: ListenerConfig,
    pub upstream: UpstreamConfig,
    pub tenants: Vec<TenantConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub address: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    #[default]
    Standalone,
    Cluster,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub kind: UpstreamKind,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub bootstrap_endpoints: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    pub id: String,
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
    #[serde(default = "default_partition_count")]
    pub partition_count: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_max_pipeline_depth")]
    pub max_pipeline_depth: usize,
    #[serde(default = "default_max_upstream_connections")]
    pub max_upstream_connections: usize,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_max_client_connections")]
    pub max_client_connections: usize,
    #[serde(default = "default_client_idle_timeout_ms")]
    pub client_idle_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: default_max_frame_bytes(),
            max_pipeline_depth: default_max_pipeline_depth(),
            max_upstream_connections: default_max_upstream_connections(),
            request_timeout_ms: default_request_timeout_ms(),
            max_client_connections: default_max_client_connections(),
            client_idle_timeout_ms: default_client_idle_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_metrics_address")]
    pub metrics_address: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_address: default_metrics_address(),
        }
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<Config> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read configuration {}", path.display()))?;
    let config: Config = toml::from_str(&contents)
        .with_context(|| format!("failed to parse configuration {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!(
                "unsupported configuration schema_version {}; expected 1",
                self.schema_version
            );
        }
        if self.listener.address.is_empty() {
            bail!("listener.address must not be empty");
        }
        match self.upstream.kind {
            UpstreamKind::Standalone if self.upstream.address.is_empty() => {
                bail!("upstream.address must not be empty for a standalone upstream");
            }
            UpstreamKind::Cluster
                if self.upstream.address.is_empty()
                    && self.upstream.bootstrap_endpoints.is_empty() =>
            {
                bail!(
                    "upstream.address or upstream.bootstrap_endpoints is required for a Cluster upstream"
                );
            }
            _ => {}
        }
        if self
            .upstream
            .bootstrap_endpoints
            .iter()
            .any(|endpoint| endpoint.is_empty())
        {
            bail!("upstream.bootstrap_endpoints must not contain empty endpoints");
        }
        if self.tenants.is_empty() {
            bail!("at least one tenant is required");
        }
        if self.limits.max_frame_bytes < 64 {
            bail!("limits.max_frame_bytes must be at least 64");
        }
        if self.limits.max_pipeline_depth == 0 {
            bail!("limits.max_pipeline_depth must be greater than zero");
        }
        if self.limits.max_upstream_connections == 0 {
            bail!("limits.max_upstream_connections must be greater than zero");
        }
        if self.limits.request_timeout_ms == 0 {
            bail!("limits.request_timeout_ms must be greater than zero");
        }
        if self.limits.max_client_connections == 0 {
            bail!("limits.max_client_connections must be greater than zero");
        }
        if self.limits.client_idle_timeout_ms == 0 {
            bail!("limits.client_idle_timeout_ms must be greater than zero");
        }

        let mut tenant_ids = HashSet::new();
        let mut credentials = HashSet::new();
        for tenant in &self.tenants {
            if tenant.id.is_empty()
                || !tenant
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                bail!(
                    "tenant id {:?} must contain only ASCII letters, digits, '-' or '_'",
                    tenant.id
                );
            }
            if !tenant_ids.insert(&tenant.id) {
                bail!("tenant id {:?} is duplicated", tenant.id);
            }
            if tenant.password.is_empty() {
                bail!("tenant {:?} password must not be empty", tenant.id);
            }
            if !tenant.partition_count.is_power_of_two() || tenant.partition_count == 0 {
                bail!(
                    "tenant {:?} partition_count must be a nonzero power of two",
                    tenant.id
                );
            }
            if tenant.partition_count > 4096 {
                bail!(
                    "tenant {:?} partition_count must not exceed 4096",
                    tenant.id
                );
            }
            let credential = (
                tenant.username.as_deref().unwrap_or(""),
                tenant.password.as_str(),
            );
            if !credentials.insert(credential) {
                bail!("tenant {:?} has duplicate client credentials", tenant.id);
            }
        }
        Ok(())
    }
}

fn default_partition_count() -> u16 {
    256
}

fn default_max_frame_bytes() -> usize {
    1024 * 1024
}

fn default_max_pipeline_depth() -> usize {
    128
}

fn default_max_upstream_connections() -> usize {
    64
}

fn default_request_timeout_ms() -> u64 {
    1_000
}

fn default_max_client_connections() -> usize {
    1_024
}

fn default_client_idle_timeout_ms() -> u64 {
    300_000
}

fn default_metrics_address() -> String {
    "127.0.0.1:9090".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_layout_breaking_partition_count() {
        let config = Config {
            schema_version: 1,
            listener: ListenerConfig {
                address: "127.0.0.1:6379".to_owned(),
            },
            upstream: UpstreamConfig {
                kind: UpstreamKind::Standalone,
                bootstrap_endpoints: Vec::new(),
                address: "127.0.0.1:6380".to_owned(),
                username: None,
                password: None,
            },
            tenants: vec![TenantConfig {
                id: "payments".to_owned(),
                username: None,
                password: "secret".to_owned(),
                partition_count: 3,
            }],
            limits: LimitsConfig::default(),
            observability: ObservabilityConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_cluster_bootstrap_endpoints_without_a_standalone_address() {
        let config = Config {
            schema_version: 1,
            listener: ListenerConfig {
                address: "127.0.0.1:6379".to_owned(),
            },
            upstream: UpstreamConfig {
                kind: UpstreamKind::Cluster,
                address: String::new(),
                bootstrap_endpoints: vec![
                    "redis-0.redis.svc.cluster.local:6379".to_owned(),
                    "redis-1.redis.svc.cluster.local:6379".to_owned(),
                ],
                username: None,
                password: None,
            },
            tenants: vec![TenantConfig {
                id: "payments".to_owned(),
                username: None,
                password: "secret".to_owned(),
                partition_count: 256,
            }],
            limits: LimitsConfig::default(),
            observability: ObservabilityConfig::default(),
        };
        config.validate().unwrap();
    }
}
