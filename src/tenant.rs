use crate::config::TenantConfig;
use bytes::{Bytes, BytesMut};
use std::sync::Arc;

#[derive(Debug)]
pub struct Tenant {
    id: Arc<str>,
    username: Option<Bytes>,
    password: Bytes,
    prefixes: Vec<Bytes>,
    strip_prefix: Bytes,
    pattern_prefix: Bytes,
}

#[derive(Debug, Clone)]
pub struct TenantRegistry {
    tenants: Arc<[Arc<Tenant>]>,
}

impl TenantRegistry {
    pub fn new(configs: &[TenantConfig]) -> Self {
        let tenants = configs
            .iter()
            .map(|config| Arc::new(Tenant::from_config(config)))
            .collect::<Vec<_>>();
        Self {
            tenants: tenants.into(),
        }
    }

    pub fn authenticate(&self, username: Option<&[u8]>, password: &[u8]) -> Option<Arc<Tenant>> {
        let mut matched = None;
        for tenant in self.tenants.iter() {
            let username_matches = match (&tenant.username, username) {
                (None, None) => true,
                (Some(expected), Some(actual)) => constant_time_eq(expected, actual),
                _ => false,
            };
            let password_matches = constant_time_eq(&tenant.password, password);
            if username_matches && password_matches {
                matched = Some(Arc::clone(tenant));
            }
        }
        matched
    }
}

impl Tenant {
    fn from_config(config: &TenantConfig) -> Self {
        let id: Arc<str> = Arc::from(config.id.as_str());
        let prefix_seed = format!("__rproxy:v1:{{t/{}/d/0/p/", config.id);
        let strip_prefix = Bytes::from(prefix_seed.clone());
        let prefixes = (0..config.partition_count)
            .map(|partition| Bytes::from(format!("{prefix_seed}{partition}}}:")))
            .collect();
        let pattern_prefix = Bytes::from(format!("{prefix_seed}*}}:"));
        Self {
            id,
            username: config
                .username
                .as_deref()
                .map(|username| Bytes::copy_from_slice(username.as_bytes())),
            password: Bytes::copy_from_slice(config.password.as_bytes()),
            prefixes,
            strip_prefix,
            pattern_prefix,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn rewrite_key(&self, logical_key: &[u8]) -> Bytes {
        let partition = self.partition_for(logical_key);
        let prefix = &self.prefixes[partition];
        let mut rewritten = BytesMut::with_capacity(prefix.len() + logical_key.len());
        rewritten.extend_from_slice(prefix);
        rewritten.extend_from_slice(logical_key);
        rewritten.freeze()
    }

    pub fn rewrite_pattern(&self, logical_pattern: &[u8]) -> Bytes {
        let mut rewritten =
            BytesMut::with_capacity(self.pattern_prefix.len() + logical_pattern.len());
        rewritten.extend_from_slice(&self.pattern_prefix);
        rewritten.extend_from_slice(logical_pattern);
        rewritten.freeze()
    }

    pub fn strip_key(&self, physical_key: &[u8]) -> Option<Bytes> {
        let rest = physical_key.strip_prefix(self.strip_prefix.as_ref())?;
        let partition_end = rest.windows(2).position(|window| window == b"}:")?;
        let partition = parse_partition(&rest[..partition_end])?;
        let prefix = self.prefixes.get(partition)?;
        physical_key
            .strip_prefix(prefix.as_ref())
            .map(Bytes::copy_from_slice)
    }

    pub fn slot_for_key(&self, logical_key: &[u8]) -> u16 {
        let partition = self.partition_for(logical_key);
        cluster_slot(&self.prefixes[partition])
    }
    fn partition_for(&self, logical_key: &[u8]) -> usize {
        let material = hash_tag(logical_key).unwrap_or(logical_key);
        let mut hash = FNV_OFFSET;
        for byte in self
            .id
            .as_bytes()
            .iter()
            .chain([0].iter())
            .chain(material.iter())
        {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        (hash as usize) & (self.prefixes.len() - 1)
    }
}

fn cluster_slot(physical_prefix: &[u8]) -> u16 {
    let material = hash_tag(physical_prefix).unwrap_or(physical_prefix);
    let mut crc = 0u16;
    for byte in material {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc & 0x3fff
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn hash_tag(key: &[u8]) -> Option<&[u8]> {
    let start = key.iter().position(|byte| *byte == b'{')?;
    let end = key[start + 1..].iter().position(|byte| *byte == b'}')? + start + 1;
    (end > start + 1).then_some(&key[start + 1..end])
}

fn parse_partition(value: &[u8]) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0usize, |current, byte| {
        byte.is_ascii_digit().then(|| {
            current
                .checked_mul(10)?
                .checked_add(usize::from(byte - b'0'))
        })?
    })
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    let mut difference = expected.len() ^ actual.len();
    let max_len = expected.len().max(actual.len());
    for index in 0..max_len {
        let left = expected.get(index).copied().unwrap_or(0);
        let right = actual.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> Tenant {
        Tenant::from_config(&TenantConfig {
            id: "payments".to_owned(),
            username: Some("app".to_owned()),
            password: "secret".to_owned(),
            partition_count: 256,
        })
    }

    #[test]
    fn hash_tags_preserve_colocation() {
        let tenant = tenant();
        let first = tenant.rewrite_key(b"{customer-42}:orders");
        let second = tenant.rewrite_key(b"{customer-42}:invoices");
        assert_eq!(physical_tag(&first), physical_tag(&second));
    }

    #[test]
    fn hash_tags_produce_the_same_cluster_slot() {
        let tenant = tenant();
        assert_eq!(
            tenant.slot_for_key(b"{customer-42}:orders"),
            tenant.slot_for_key(b"{customer-42}:invoices")
        );
    }

    #[test]
    fn physical_name_keeps_logical_suffix() {
        let rewritten = tenant().rewrite_key(b"cart:42");
        assert!(rewritten.starts_with(b"__rproxy:v1:{t/payments/d/0/p/"));
        assert!(rewritten.ends_with(b"}:cart:42"));
    }

    fn physical_tag(key: &[u8]) -> &[u8] {
        let start = key.iter().position(|byte| *byte == b'{').unwrap();
        let end = key[start + 1..]
            .iter()
            .position(|byte| *byte == b'}')
            .unwrap()
            + start
            + 1;
        &key[start + 1..end]
    }
}
