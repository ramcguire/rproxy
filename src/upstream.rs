use crate::{
    cluster::ClusterTopology,
    config::{UpstreamConfig, UpstreamKind},
    protocol::{encode_command, read_frame},
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{Mutex, Notify, RwLock, Semaphore},
    time::timeout,
};
pub(crate) enum Upstream {
    Standalone(ConnectionPool),
    Cluster(ClusterUpstream),
}

#[derive(Clone)]
struct Credentials {
    username: Option<Bytes>,
    password: Bytes,
}

pub(crate) struct ConnectionPool {
    address: Arc<str>,
    credentials: Option<Credentials>,
    request_timeout: Duration,
    idle: Mutex<Vec<PooledConnection>>,
    available: Arc<Notify>,
    permits: Arc<Semaphore>,
    idle_registry: Option<Arc<IdleRegistry>>,
    max_frame_bytes: usize,
}

struct PooledConnection {
    reader: BufReader<TcpStream>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

struct IdleRegistry {
    pools: Mutex<Vec<Weak<ConnectionPool>>>,
}

impl IdleRegistry {
    async fn register(&self, pool: &Arc<ConnectionPool>) {
        self.pools.lock().await.push(Arc::downgrade(pool));
    }

    async fn evict_one(&self) -> bool {
        let pools = {
            let mut pools = self.pools.lock().await;
            pools.retain(|pool| pool.strong_count() != 0);
            pools.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };
        for pool in pools {
            if pool.idle.lock().await.pop().is_some() {
                return true;
            }
        }
        false
    }
}

pub(crate) struct ClusterUpstream {
    bootstrap: Arc<[Arc<str>]>,
    credentials: Option<Credentials>,
    request_timeout: Duration,
    permits: Arc<Semaphore>,
    available: Arc<Notify>,
    idle_registry: Arc<IdleRegistry>,
    max_frame_bytes: usize,
    topology: RwLock<Arc<ClusterTopology>>,
    pools: Mutex<HashMap<Arc<str>, Arc<ConnectionPool>>>,
}

impl Upstream {
    pub fn new(
        config: &UpstreamConfig,
        max_connections: usize,
        request_timeout: Duration,
        max_frame_bytes: usize,
    ) -> Self {
        let credentials = config.password.as_deref().map(|password| Credentials {
            username: config
                .username
                .as_deref()
                .map(|username| Bytes::copy_from_slice(username.as_bytes())),
            password: Bytes::copy_from_slice(password.as_bytes()),
        });
        match config.kind {
            UpstreamKind::Standalone => Self::Standalone(ConnectionPool::new(
                Arc::from(config.address.as_str()),
                credentials,
                Arc::new(Semaphore::new(max_connections)),
                Arc::new(Notify::new()),
                None,
                request_timeout,
                max_frame_bytes,
            )),
            UpstreamKind::Cluster => {
                let mut bootstrap = Vec::with_capacity(config.bootstrap_endpoints.len() + 1);
                if !config.address.is_empty() {
                    bootstrap.push(Arc::from(config.address.as_str()));
                }
                bootstrap.extend(
                    config
                        .bootstrap_endpoints
                        .iter()
                        .map(|endpoint| Arc::from(endpoint.as_str())),
                );
                Self::Cluster(ClusterUpstream {
                    bootstrap: bootstrap.into(),
                    credentials,
                    request_timeout,
                    permits: Arc::new(Semaphore::new(max_connections)),
                    available: Arc::new(Notify::new()),
                    idle_registry: Arc::new(IdleRegistry {
                        pools: Mutex::new(Vec::new()),
                    }),
                    max_frame_bytes,
                    topology: RwLock::new(Arc::new(ClusterTopology::empty())),
                    pools: Mutex::new(HashMap::new()),
                })
            }
        }
    }

    pub fn is_cluster(&self) -> bool {
        matches!(self, Self::Cluster(_))
    }

    pub async fn execute(&self, slot: Option<u16>, request: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Standalone(pool) => pool.execute(request).await,
            Self::Cluster(cluster) => {
                cluster
                    .execute(
                        slot.ok_or_else(|| anyhow::anyhow!("cluster request has no key slot"))?,
                        request,
                    )
                    .await
            }
        }
    }

    pub async fn execute_transaction(
        &self,
        slot: Option<u16>,
        requests: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        match self {
            Self::Standalone(pool) => pool.execute_transaction(requests).await,
            Self::Cluster(cluster) => {
                cluster
                    .execute_transaction(
                        slot.ok_or_else(|| anyhow::anyhow!("cluster transaction has no key slot"))?,
                        requests,
                    )
                    .await
            }
        }
    }
}

impl ClusterUpstream {
    async fn execute(&self, slot: u16, request: &[u8]) -> Result<Vec<u8>> {
        let mut address = self.address_for_slot(slot).await?;
        for redirect_count in 0..=1 {
            let response = self
                .pool(Arc::clone(&address))
                .await
                .execute(request)
                .await?;
            let Some(redirect) = parse_redirect(&response, &address) else {
                return Ok(response);
            };
            if redirect.slot != slot || redirect_count == 1 {
                bail!("cluster redirection retry limit reached");
            }
            match redirect.kind {
                RedirectKind::Moved => {
                    let _ = self.refresh().await;
                    self.set_slot(slot, Arc::clone(&redirect.address)).await;
                    address = redirect.address;
                }
                RedirectKind::Ask => {
                    return self
                        .pool(redirect.address)
                        .await
                        .execute_asking(request)
                        .await;
                }
            }
        }
        unreachable!("redirect loop exits by returning or failing")
    }

    async fn execute_transaction(&self, slot: u16, requests: &[Vec<u8>]) -> Result<Vec<u8>> {
        let address = self.address_for_slot(slot).await?;
        self.pool(address).await.execute_transaction(requests).await
    }

    async fn address_for_slot(&self, slot: u16) -> Result<Arc<str>> {
        if let Some(address) = self.topology.read().await.address(slot).cloned() {
            return Ok(address);
        }
        self.refresh().await?;
        self.topology
            .read()
            .await
            .address(slot)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no Cluster primary owns slot {slot}"))
    }

    async fn refresh(&self) -> Result<()> {
        let mut failures = Vec::new();
        for address in self.bootstrap.iter() {
            match self
                .pool(Arc::clone(address))
                .await
                .execute(b"*2\r\n$7\r\nCLUSTER\r\n$5\r\nSLOTS\r\n")
                .await
            {
                Ok(response) => match ClusterTopology::from_cluster_slots(&response) {
                    Ok(topology) => {
                        *self.topology.write().await = Arc::new(topology);
                        return Ok(());
                    }
                    Err(error) => failures.push(format!("{address}: {error}")),
                },
                Err(error) => failures.push(format!("{address}: {error}")),
            }
        }
        bail!(
            "could not refresh Cluster topology: {}",
            failures.join("; ")
        )
    }

    async fn set_slot(&self, slot: u16, address: Arc<str>) {
        let current = Arc::clone(&*self.topology.read().await);
        *self.topology.write().await = Arc::new(current.with_slot(slot, address));
    }

    async fn pool(&self, address: Arc<str>) -> Arc<ConnectionPool> {
        let mut pools = self.pools.lock().await;
        if let Some(pool) = pools.get(&address) {
            return Arc::clone(pool);
        }
        let pool = Arc::new(ConnectionPool::new(
            Arc::clone(&address),
            self.credentials.clone(),
            Arc::clone(&self.permits),
            Arc::clone(&self.available),
            Some(Arc::clone(&self.idle_registry)),
            self.request_timeout,
            self.max_frame_bytes,
        ));
        self.idle_registry.register(&pool).await;
        pools.insert(address, Arc::clone(&pool));
        pool
    }
}

impl ConnectionPool {
    fn new(
        address: Arc<str>,
        credentials: Option<Credentials>,
        permits: Arc<Semaphore>,
        available: Arc<Notify>,
        idle_registry: Option<Arc<IdleRegistry>>,
        request_timeout: Duration,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            address,
            credentials,
            request_timeout,
            idle: Mutex::new(Vec::new()),
            available,
            permits,
            idle_registry,
            max_frame_bytes,
        }
    }

    async fn execute(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut connection = self.connection().await?;
        let result = timeout(self.request_timeout, async {
            connection.reader.get_mut().write_all(request).await?;
            read_frame(&mut connection.reader, self.max_frame_bytes)
                .await?
                .ok_or_else(|| anyhow::anyhow!("upstream closed before sending a response"))
        })
        .await
        .context("upstream request timed out")?;
        if result.is_ok() {
            self.release(connection).await;
        } else {
            drop(connection);
            self.available.notify_one();
        }
        result.context("upstream request failed")
    }

    async fn execute_asking(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut connection = self.connection().await?;
        let result = timeout(self.request_timeout, async {
            connection
                .reader
                .get_mut()
                .write_all(b"*1\r\n$6\r\nASKING\r\n")
                .await?;
            if read_frame(&mut connection.reader, self.max_frame_bytes)
                .await?
                .as_deref()
                != Some(b"+OK\r\n")
            {
                bail!("upstream rejected ASKING");
            }
            connection.reader.get_mut().write_all(request).await?;
            read_frame(&mut connection.reader, self.max_frame_bytes)
                .await?
                .ok_or_else(|| anyhow::anyhow!("upstream closed before sending a response"))
        })
        .await
        .context("upstream ASK request timed out")?;
        if result.is_ok() {
            self.release(connection).await;
        } else {
            drop(connection);
            self.available.notify_one();
        }
        result.context("upstream ASK request failed")
    }

    async fn execute_transaction(&self, requests: &[Vec<u8>]) -> Result<Vec<u8>> {
        let mut connection = self.connection().await?;
        let result = timeout(self.request_timeout, async {
            connection
                .reader
                .get_mut()
                .write_all(b"*1\r\n$5\r\nMULTI\r\n")
                .await?;
            if read_frame(&mut connection.reader, self.max_frame_bytes)
                .await?
                .as_deref()
                != Some(b"+OK\r\n")
            {
                bail!("upstream rejected MULTI");
            }
            for request in requests {
                connection.reader.get_mut().write_all(request).await?;
                if read_frame(&mut connection.reader, self.max_frame_bytes)
                    .await?
                    .as_deref()
                    != Some(b"+QUEUED\r\n")
                {
                    bail!("upstream rejected a queued transaction command");
                }
            }
            connection
                .reader
                .get_mut()
                .write_all(b"*1\r\n$4\r\nEXEC\r\n")
                .await?;
            read_frame(&mut connection.reader, self.max_frame_bytes)
                .await?
                .ok_or_else(|| anyhow::anyhow!("upstream closed before EXEC response"))
        })
        .await
        .context("upstream transaction timed out")?;
        if result.is_ok() {
            self.release(connection).await;
        } else {
            drop(connection);
            self.available.notify_one();
        }
        result.context("upstream transaction failed")
    }

    async fn release(&self, connection: PooledConnection) {
        self.idle.lock().await.push(connection);
        self.available.notify_waiters();
    }

    async fn connection(&self) -> Result<PooledConnection> {
        loop {
            if let Some(connection) = self.idle.lock().await.pop() {
                return Ok(connection);
            }
            match Arc::clone(&self.permits).try_acquire_owned() {
                Ok(permit) => {
                    let result = self.connect(permit).await;
                    if result.is_err() {
                        self.available.notify_waiters();
                    }
                    return result;
                }
                Err(tokio::sync::TryAcquireError::NoPermits) => {
                    if let Some(registry) = &self.idle_registry
                        && registry.evict_one().await
                    {
                        continue;
                    }
                    timeout(self.request_timeout, self.available.notified())
                        .await
                        .context("timed out waiting for an upstream connection")?;
                }
                Err(tokio::sync::TryAcquireError::Closed) => {
                    bail!("upstream pool is closed");
                }
            }
        }
    }

    async fn connect(&self, permit: tokio::sync::OwnedSemaphorePermit) -> Result<PooledConnection> {
        let stream = timeout(
            self.request_timeout,
            TcpStream::connect(self.address.as_ref()),
        )
        .await
        .with_context(|| format!("timed out connecting to upstream {}", self.address))??;
        stream.set_nodelay(true)?;
        let mut reader = BufReader::new(stream);
        if let Some(credentials) = &self.credentials {
            let mut auth = vec![Bytes::from_static(b"AUTH")];
            if let Some(username) = &credentials.username {
                auth.push(username.clone());
            }
            auth.push(credentials.password.clone());
            let response = timeout(self.request_timeout, async {
                reader.get_mut().write_all(&encode_command(&auth)).await?;
                read_frame(&mut reader, self.max_frame_bytes)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("upstream closed during AUTH"))
            })
            .await
            .context("upstream authentication timed out")??;
            if response != b"+OK\r\n" {
                bail!("upstream authentication failed");
            }
        }
        Ok(PooledConnection {
            reader,
            _permit: permit,
        })
    }
}

#[derive(Debug)]
struct Redirect {
    kind: RedirectKind,
    slot: u16,
    address: Arc<str>,
}

#[derive(Debug)]
enum RedirectKind {
    Moved,
    Ask,
}

fn parse_redirect(response: &[u8], current_address: &str) -> Option<Redirect> {
    let line = response.strip_prefix(b"-")?.strip_suffix(b"\r\n")?;
    let mut fields = std::str::from_utf8(line).ok()?.split_ascii_whitespace();
    let kind = match fields.next()? {
        "MOVED" => RedirectKind::Moved,
        "ASK" => RedirectKind::Ask,
        _ => return None,
    };
    let slot = fields.next()?.parse::<u16>().ok()?;
    let endpoint = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let address = redirect_address(endpoint, current_address)?;
    Some(Redirect {
        kind,
        slot,
        address,
    })
}

fn redirect_address(endpoint: &str, current_address: &str) -> Option<Arc<str>> {
    if !endpoint.starts_with(':') {
        return Some(Arc::from(endpoint));
    }
    let port = endpoint.strip_prefix(':')?;
    let host = if current_address.starts_with('[') {
        current_address.rsplit_once("]:").map(|(host, _)| host)?
    } else {
        current_address.rsplit_once(':').map(|(host, _)| host)?
    };
    Some(Arc::from(format!("{host}:{port}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_moved_and_empty_host_redirects() {
        let redirect = parse_redirect(b"-MOVED 42 127.0.0.1:6380\r\n", "127.0.0.1:6379").unwrap();
        assert!(matches!(redirect.kind, RedirectKind::Moved));
        assert_eq!(redirect.slot, 42);
        assert_eq!(redirect.address.as_ref(), "127.0.0.1:6380");

        let redirect = parse_redirect(b"-ASK 42 :6380\r\n", "127.0.0.1:6379").unwrap();
        assert!(matches!(redirect.kind, RedirectKind::Ask));
        assert_eq!(redirect.address.as_ref(), "127.0.0.1:6380");
    }

    #[tokio::test]
    async fn refreshes_topology_and_routes_to_the_slot_primary() {
        use crate::protocol::read_command;
        use tokio::{
            io::{AsyncWriteExt, BufReader},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server_address = address.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let slots = read_command(&mut reader, 4096).await.unwrap().unwrap();
            assert_eq!(
                slots.args,
                [Bytes::from_static(b"CLUSTER"), Bytes::from_static(b"SLOTS")]
            );
            let topology = format!(
                "*1\r\n*3\r\n:42\r\n:42\r\n*2\r\n$9\r\n127.0.0.1\r\n:{}\r\n",
                server_address.rsplit_once(':').unwrap().1
            );
            writer.write_all(topology.as_bytes()).await.unwrap();

            let get = read_command(&mut reader, 4096).await.unwrap().unwrap();
            assert_eq!(
                get.args,
                [Bytes::from_static(b"GET"), Bytes::from_static(b"key")]
            );
            writer.write_all(b"$5\r\nvalue\r\n").await.unwrap();
        });
        let cluster = ClusterUpstream {
            bootstrap: vec![Arc::from(address.as_str())].into(),
            credentials: None,
            request_timeout: Duration::from_secs(1),
            permits: Arc::new(Semaphore::new(1)),
            available: Arc::new(Notify::new()),
            idle_registry: Arc::new(IdleRegistry {
                pools: Mutex::new(Vec::new()),
            }),
            max_frame_bytes: 4096,
            topology: RwLock::new(Arc::new(ClusterTopology::empty())),
            pools: Mutex::new(HashMap::new()),
        };

        let response = cluster
            .execute(42, b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
            .await
            .unwrap();
        assert_eq!(response, b"$5\r\nvalue\r\n");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn retries_moved_requests_on_the_redirected_primary() {
        use crate::protocol::read_command;
        use tokio::{
            io::{AsyncWriteExt, BufReader},
            net::TcpListener,
        };

        let redirected_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirected_address = redirected_listener.local_addr().unwrap().to_string();
        let redirected = tokio::spawn(async move {
            let (stream, _) = redirected_listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let request = read_command(&mut reader, 4096).await.unwrap().unwrap();
            assert_eq!(request.args[0], b"GET"[..]);
            writer.write_all(b"$5\r\nvalue\r\n").await.unwrap();
        });

        let bootstrap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bootstrap_address = bootstrap_listener.local_addr().unwrap().to_string();
        let bootstrap_port = bootstrap_address.rsplit_once(':').unwrap().1.to_owned();
        let redirected_port = redirected_address.rsplit_once(':').unwrap().1.to_owned();
        let bootstrap = tokio::spawn(async move {
            let (stream, _) = bootstrap_listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args[0],
                b"CLUSTER"[..]
            );
            writer
                .write_all(
                    format!(
                        "*1\r\n*3\r\n:42\r\n:42\r\n*2\r\n$9\r\n127.0.0.1\r\n:{bootstrap_port}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args[0],
                b"GET"[..]
            );
            writer
                .write_all(format!("-MOVED 42 127.0.0.1:{redirected_port}\r\n").as_bytes())
                .await
                .unwrap();
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args[0],
                b"CLUSTER"[..]
            );
            writer
                .write_all(
                    format!(
                        "*1\r\n*3\r\n:42\r\n:42\r\n*2\r\n$9\r\n127.0.0.1\r\n:{redirected_port}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });

        let cluster = test_cluster(bootstrap_address);
        assert_eq!(
            cluster
                .execute(42, b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
                .await
                .unwrap(),
            b"$5\r\nvalue\r\n"
        );
        bootstrap.await.unwrap();
        redirected.await.unwrap();
    }

    #[tokio::test]
    async fn sends_asking_before_retrying_ask_redirects() {
        use crate::protocol::read_command;
        use tokio::{
            io::{AsyncWriteExt, BufReader},
            net::TcpListener,
        };

        let redirected_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirected_address = redirected_listener.local_addr().unwrap().to_string();
        let redirected = tokio::spawn(async move {
            let (stream, _) = redirected_listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args,
                [Bytes::from_static(b"ASKING")]
            );
            writer.write_all(b"+OK\r\n").await.unwrap();
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args[0],
                b"GET"[..]
            );
            writer.write_all(b"$5\r\nvalue\r\n").await.unwrap();
        });

        let bootstrap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bootstrap_address = bootstrap_listener.local_addr().unwrap().to_string();
        let bootstrap_port = bootstrap_address.rsplit_once(':').unwrap().1.to_owned();
        let redirected_port = redirected_address.rsplit_once(':').unwrap().1.to_owned();
        let bootstrap = tokio::spawn(async move {
            let (stream, _) = bootstrap_listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args[0],
                b"CLUSTER"[..]
            );
            writer
                .write_all(
                    format!(
                        "*1\r\n*3\r\n:42\r\n:42\r\n*2\r\n$9\r\n127.0.0.1\r\n:{bootstrap_port}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            assert_eq!(
                read_command(&mut reader, 4096).await.unwrap().unwrap().args[0],
                b"GET"[..]
            );
            writer
                .write_all(format!("-ASK 42 127.0.0.1:{redirected_port}\r\n").as_bytes())
                .await
                .unwrap();
        });

        let cluster = test_cluster(bootstrap_address);
        assert_eq!(
            cluster
                .execute(42, b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
                .await
                .unwrap(),
            b"$5\r\nvalue\r\n"
        );
        bootstrap.await.unwrap();
        redirected.await.unwrap();
    }

    fn test_cluster(bootstrap: String) -> ClusterUpstream {
        ClusterUpstream {
            bootstrap: vec![Arc::from(bootstrap.as_str())].into(),
            credentials: None,
            request_timeout: Duration::from_secs(1),
            permits: Arc::new(Semaphore::new(1)),
            available: Arc::new(Notify::new()),
            idle_registry: Arc::new(IdleRegistry {
                pools: Mutex::new(Vec::new()),
            }),
            max_frame_bytes: 4096,
            topology: RwLock::new(Arc::new(ClusterTopology::empty())),
            pools: Mutex::new(HashMap::new()),
        }
    }
}
