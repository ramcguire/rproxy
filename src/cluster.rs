use anyhow::{Result, bail};
use std::sync::Arc;

pub const SLOT_COUNT: usize = 16_384;

#[derive(Clone, Debug)]
pub struct ClusterTopology {
    slots: Box<[Option<Arc<str>>]>,
}

impl ClusterTopology {
    pub fn empty() -> Self {
        Self {
            slots: vec![None; SLOT_COUNT].into_boxed_slice(),
        }
    }

    pub fn from_cluster_slots(response: &[u8]) -> Result<Self> {
        let value = parse_response(response)?;
        let Value::Array(ranges) = value else {
            bail!("CLUSTER SLOTS response must be an array");
        };
        let mut topology = Self::empty();
        for range in ranges {
            let Value::Array(parts) = range else {
                bail!("CLUSTER SLOTS range must be an array");
            };
            let [start, end, primary, ..] = parts.as_slice() else {
                bail!("CLUSTER SLOTS range is incomplete");
            };
            let start = slot(start)?;
            let end = slot(end)?;
            if start > end {
                bail!("CLUSTER SLOTS range has an invalid slot order");
            }
            let address = primary_address(primary)?;
            for entry in &mut topology.slots[start..=end] {
                if entry.is_some() {
                    bail!("CLUSTER SLOTS ranges overlap");
                }
                *entry = Some(Arc::clone(&address));
            }
        }
        Ok(topology)
    }

    pub fn address(&self, slot: u16) -> Option<&Arc<str>> {
        self.slots.get(usize::from(slot)).and_then(Option::as_ref)
    }

    pub fn with_slot(&self, slot: u16, address: Arc<str>) -> Self {
        let mut slots = self.slots.clone();
        slots[usize::from(slot)] = Some(address);
        Self { slots }
    }
}

fn slot(value: &Value) -> Result<usize> {
    let Value::Integer(value) = value else {
        bail!("CLUSTER SLOTS slot must be an integer");
    };
    usize::try_from(*value)
        .ok()
        .filter(|slot| *slot < SLOT_COUNT)
        .ok_or_else(|| anyhow::anyhow!("CLUSTER SLOTS slot is out of range"))
}

fn primary_address(value: &Value) -> Result<Arc<str>> {
    let Value::Array(parts) = value else {
        bail!("CLUSTER SLOTS primary node must be an array");
    };
    let [host, port, ..] = parts.as_slice() else {
        bail!("CLUSTER SLOTS primary node is incomplete");
    };
    let Value::Bulk(host) = host else {
        bail!("CLUSTER SLOTS primary host must be a bulk string");
    };
    let Value::Integer(port) = port else {
        bail!("CLUSTER SLOTS primary port must be an integer");
    };
    let port = u16::try_from(*port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow::anyhow!("CLUSTER SLOTS primary port is invalid"))?;
    let host = std::str::from_utf8(host)
        .map_err(|_| anyhow::anyhow!("CLUSTER SLOTS host is not UTF-8"))?;
    if host.is_empty() {
        bail!("CLUSTER SLOTS primary host is empty");
    }
    let address = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(Arc::from(address))
}

#[derive(Debug)]
enum Value {
    Integer(i64),
    Bulk(Vec<u8>),
    Array(Vec<Value>),
}

fn parse_response(input: &[u8]) -> Result<Value> {
    let mut offset = 0;
    let value = parse_value(input, &mut offset)?;
    if offset != input.len() {
        bail!("trailing bytes in CLUSTER SLOTS response");
    }
    Ok(value)
}

fn parse_value(input: &[u8], offset: &mut usize) -> Result<Value> {
    let kind = *input
        .get(*offset)
        .ok_or_else(|| anyhow::anyhow!("truncated CLUSTER SLOTS response"))?;
    *offset += 1;
    let header = take_line(input, offset)?;
    match kind {
        b':' => Ok(Value::Integer(parse_i64(header)?)),
        b'$' => {
            let length = parse_i64(header)?;
            if length < 0 {
                bail!("null bulk strings are not valid in CLUSTER SLOTS response");
            }
            let length =
                usize::try_from(length).map_err(|_| anyhow::anyhow!("bulk length overflow"))?;
            let end = offset
                .checked_add(length)
                .and_then(|end| end.checked_add(2))
                .ok_or_else(|| anyhow::anyhow!("bulk length overflow"))?;
            if input.get(*offset + length..end) != Some(b"\r\n") {
                bail!("invalid CLUSTER SLOTS bulk string");
            }
            let value = input[*offset..*offset + length].to_vec();
            *offset = end;
            Ok(Value::Bulk(value))
        }
        b'*' => {
            let count = parse_i64(header)?;
            if count < 0 {
                bail!("null arrays are not valid in CLUSTER SLOTS response");
            }
            let count =
                usize::try_from(count).map_err(|_| anyhow::anyhow!("array length overflow"))?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(parse_value(input, offset)?);
            }
            Ok(Value::Array(values))
        }
        _ => bail!("unsupported CLUSTER SLOTS response type"),
    }
}

fn take_line<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let rest = input
        .get(*offset..)
        .ok_or_else(|| anyhow::anyhow!("truncated CLUSTER SLOTS response"))?;
    let end = rest
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| anyhow::anyhow!("unterminated CLUSTER SLOTS response"))?;
    let line = &rest[..end];
    *offset += end + 2;
    Ok(line)
}

fn parse_i64(value: &[u8]) -> Result<i64> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid integer in CLUSTER SLOTS response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_slot_ranges_and_ipv6_nodes() {
        let response = b"*2\r\n*3\r\n:0\r\n:1\r\n*2\r\n$9\r\n127.0.0.1\r\n:6379\r\n*3\r\n:2\r\n:3\r\n*2\r\n$3\r\n::1\r\n:6380\r\n";
        let topology = ClusterTopology::from_cluster_slots(response).unwrap();
        assert_eq!(topology.address(0).unwrap().as_ref(), "127.0.0.1:6379");
        assert_eq!(topology.address(1).unwrap().as_ref(), "127.0.0.1:6379");
        assert_eq!(topology.address(2).unwrap().as_ref(), "[::1]:6380");
        assert!(topology.address(4).is_none());
    }

    #[test]
    fn rejects_overlapping_slot_ranges() {
        let response = b"*2\r\n*3\r\n:0\r\n:1\r\n*2\r\n$9\r\n127.0.0.1\r\n:6379\r\n*3\r\n:1\r\n:2\r\n*2\r\n$9\r\n127.0.0.1\r\n:6380\r\n";
        assert!(ClusterTopology::from_cluster_slots(response).is_err());
    }
}
