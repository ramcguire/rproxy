use crate::{
    command_catalog::{KeyMode, Plan, ResponsePolicy, key_indices, plan, rewrite},
    config::Config,
    protocol::{bulk, encode_command, error, read_command, simple},
    response::{sanitize_first_key_array, sanitize_key_array, sanitize_scan, sanitize_stream_read},
    telemetry::{Metrics, serve_http},
    tenant::{Tenant, TenantRegistry},
    upstream::Upstream,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Semaphore,
    time::timeout,
};

pub struct AppState {
    tenants: TenantRegistry,
    upstream: Upstream,
    metrics: Arc<Metrics>,
    max_frame_bytes: usize,
    max_pipeline_depth: usize,
    client_permits: Arc<Semaphore>,
    client_idle_timeout: Duration,
}

struct Transaction {
    commands: Vec<crate::protocol::Command>,
    bytes: usize,
}

impl AppState {
    pub fn from_config(config: &Config) -> Self {
        Self {
            tenants: TenantRegistry::new(&config.tenants),
            upstream: Upstream::new(
                &config.upstream,
                config.limits.max_upstream_connections,
                Duration::from_millis(config.limits.request_timeout_ms),
                config.limits.max_frame_bytes,
            ),
            metrics: Arc::new(Metrics::default()),
            max_frame_bytes: config.limits.max_frame_bytes,
            max_pipeline_depth: config.limits.max_pipeline_depth,
            client_permits: Arc::new(Semaphore::new(config.limits.max_client_connections)),
            client_idle_timeout: Duration::from_millis(config.limits.client_idle_timeout_ms),
        }
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }
}

pub async fn run(config: Config) -> Result<()> {
    let state = Arc::new(AppState::from_config(&config));
    let redis_listener = TcpListener::bind(&config.listener.address)
        .await
        .with_context(|| format!("failed to bind Redis listener {}", config.listener.address))?;
    let metrics_listener = TcpListener::bind(&config.observability.metrics_address)
        .await
        .with_context(|| {
            format!(
                "failed to bind metrics listener {}",
                config.observability.metrics_address
            )
        })?;

    tracing::info!(
        listener = %config.listener.address,
        metrics = %config.observability.metrics_address,
        upstream = %config.upstream.address,
        "rproxy started"
    );

    let metrics = state.metrics();
    tokio::spawn(async move {
        if let Err(error) = serve_http(metrics_listener, metrics).await {
            tracing::error!(%error, "metrics server stopped");
        }
    });

    serve(redis_listener, state).await
}

pub async fn serve(listener: TcpListener, state: Arc<AppState>) -> Result<()> {
    loop {
        let permit = Arc::clone(&state.client_permits)
            .acquire_owned()
            .await
            .context("client connection limit is closed")?;
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, state).await {
                tracing::debug!(%peer, %error, "client connection closed with error");
            }
        });
    }
}

pub async fn handle_connection(stream: TcpStream, state: Arc<AppState>) -> Result<()> {
    state.metrics.accepted_connection();
    let (reader, mut writer) = stream.into_split();
    let reader_capacity = state
        .max_frame_bytes
        .min(state.max_pipeline_depth.saturating_mul(1024))
        .max(1024);
    let mut reader = BufReader::with_capacity(reader_capacity, reader);
    let result = handle_session(&mut reader, &mut writer, &state).await;
    state.metrics.closed_connection();
    result
}

async fn handle_session(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    state: &AppState,
) -> Result<()> {
    let mut tenant: Option<Arc<Tenant>> = None;
    let mut transaction = None::<Transaction>;

    loop {
        let command = match timeout(
            state.client_idle_timeout,
            read_command(reader, state.max_frame_bytes),
        )
        .await
        {
            Err(_) => return Ok(()),
            Ok(Ok(Some(command))) => command,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(read_error)) => {
                send(writer, &error("ERR protocol error"), &state.metrics).await?;
                return Err(read_error.into());
            }
        };
        state.metrics.request();
        state.metrics.received_bytes(
            command
                .args
                .iter()
                .map(|argument| argument.len() as u64)
                .sum(),
        );

        let planned = plan(&command);
        if let Some(queued) = transaction.as_mut() {
            let response = match planned {
                Ok(Plan::Exec) => match tenant.as_ref() {
                    None => error("NOAUTH Authentication required."),
                    Some(tenant) => {
                        let queued = transaction.take().expect("transaction state was present");
                        if queued.commands.is_empty() {
                            b"*0\r\n".to_vec()
                        } else {
                            match encode_transaction(
                                &queued.commands,
                                tenant,
                                state.upstream.is_cluster(),
                            ) {
                                Err(message) => {
                                    state.metrics.rejected();
                                    error(message)
                                }
                                Ok((slot, requests)) => {
                                    match state.upstream.execute_transaction(slot, &requests).await
                                    {
                                        Ok(response) => response,
                                        Err(upstream_error) => {
                                            state.metrics.upstream_failed();
                                            tracing::warn!(%upstream_error, tenant = tenant.id(), "upstream transaction failed");
                                            error("TRYAGAIN upstream transaction failed")
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                Ok(Plan::Discard) => {
                    transaction = None;
                    simple("OK")
                }
                Ok(Plan::Forward {
                    keys,
                    key_mode: KeyMode::Literal,
                    response: ResponsePolicy::Raw,
                }) => match key_indices(&command, keys) {
                    Err(message) => {
                        state.metrics.rejected();
                        error(message)
                    }
                    Ok(_) if queued.commands.len() >= state.max_pipeline_depth => {
                        state.metrics.rejected();
                        error("ERR transaction queue limit exceeded")
                    }
                    Ok(_)
                        if queued.bytes.saturating_add(command_payload_bytes(&command))
                            > state.max_frame_bytes =>
                    {
                        state.metrics.rejected();
                        error("ERR transaction byte limit exceeded")
                    }
                    Ok(_) => {
                        queued.bytes += command_payload_bytes(&command);
                        queued.commands.push(command);
                        simple("QUEUED")
                    }
                },
                Ok(Plan::Forward { .. }) => {
                    state.metrics.rejected();
                    error("ERR command is not supported inside a phase 2 transaction")
                }
                _ => {
                    state.metrics.rejected();
                    error("ERR command is not supported inside a phase 2 transaction")
                }
            };
            send(writer, &response, &state.metrics).await?;
            continue;
        }

        let response = match planned {
            Ok(Plan::Auth) => {
                authenticate(&command.args, &state.tenants, &mut tenant, &state.metrics)
            }
            Ok(Plan::Hello) => hello(
                &command.args,
                &state.tenants,
                &mut tenant,
                &state.metrics,
                state.upstream.is_cluster(),
            ),
            Ok(Plan::Quit) => {
                send(writer, &simple("OK"), &state.metrics).await?;
                return Ok(());
            }
            Ok(Plan::Ping) => match require_tenant(&tenant) {
                Ok(()) => {
                    if command.args.len() == 2 {
                        bulk(&command.args[1])
                    } else {
                        simple("PONG")
                    }
                }
                Err(message) => error(message),
            },
            Ok(Plan::Echo) => match require_tenant(&tenant) {
                Ok(()) => bulk(&command.args[1]),
                Err(message) => error(message),
            },
            Ok(Plan::Multi) => match require_tenant(&tenant) {
                Ok(()) => {
                    transaction = Some(Transaction {
                        commands: Vec::new(),
                        bytes: 0,
                    });
                    simple("OK")
                }
                Err(message) => error(message),
            },
            Ok(Plan::Exec) => error("ERR EXEC without MULTI"),
            Ok(Plan::Discard) => error("ERR DISCARD without MULTI"),
            Ok(Plan::Scan) if state.upstream.is_cluster() => {
                state.metrics.rejected();
                error("ERR SCAN is not supported against a clustered upstream")
            }
            Ok(Plan::Scan) => match tenant.as_ref() {
                None => error("NOAUTH Authentication required."),
                Some(tenant) => match rewrite_scan(&command, tenant) {
                    Err(message) => {
                        state.metrics.rejected();
                        error(message)
                    }
                    Ok(rewritten) => match state
                        .upstream
                        .execute(None, &encode_command(&rewritten))
                        .await
                    {
                        Ok(response) => match sanitize_scan(&response, tenant) {
                            Ok(sanitized) => sanitized,
                            Err(sanitize_error) => {
                                state.metrics.upstream_failed();
                                tracing::warn!(%sanitize_error, tenant = tenant.id(), "upstream scan response was invalid");
                                error("TRYAGAIN upstream response could not be sanitized")
                            }
                        },
                        Err(upstream_error) => {
                            state.metrics.upstream_failed();
                            tracing::warn!(%upstream_error, tenant = tenant.id(), "upstream request failed");
                            error("TRYAGAIN upstream request failed")
                        }
                    },
                },
            },
            Ok(Plan::Forward {
                keys,
                key_mode,
                response: response_policy,
            }) => match tenant.as_ref() {
                None => error("NOAUTH Authentication required."),
                Some(tenant) => match key_indices(&command, keys) {
                    Err(message) => {
                        state.metrics.rejected();
                        error(message)
                    }
                    Ok(key_indices) => {
                        let slot = match key_mode {
                            KeyMode::Literal => {
                                slot_for_keys(tenant, &command, &key_indices).map(Some)
                            }
                            KeyMode::Pattern if state.upstream.is_cluster() => Err(
                                "ERR pattern commands are not supported against a clustered upstream",
                            ),
                            KeyMode::Pattern => Ok(None),
                        };
                        match slot {
                            Err(message) => {
                                state.metrics.rejected();
                                error(message)
                            }
                            Ok(slot) => {
                                let rewritten =
                                    rewrite(&command, &key_indices, |key| match key_mode {
                                        KeyMode::Literal => tenant.rewrite_key(key),
                                        KeyMode::Pattern => tenant.rewrite_pattern(key),
                                    });
                                let request = encode_command(&rewritten);
                                match state.upstream.execute(slot, &request).await {
                                    Ok(response) => match response_policy {
                                        ResponsePolicy::Raw => response,
                                        ResponsePolicy::KeyArray => {
                                            sanitize_key_array(&response, tenant).unwrap_or_else(
                                                |sanitize_error| {
                                                    state.metrics.upstream_failed();
                                                    tracing::warn!(%sanitize_error, tenant = tenant.id(), "upstream key response was invalid");
                                                    error(
                                                        "TRYAGAIN upstream response could not be sanitized",
                                                    )
                                                },
                                            )
                                        }
                                        ResponsePolicy::FirstKeyArray => {
                                            sanitize_first_key_array(&response, tenant)
                                                .unwrap_or_else(|sanitize_error| {
                                                    state.metrics.upstream_failed();
                                                    tracing::warn!(%sanitize_error, tenant = tenant.id(), "upstream keyed response was invalid");
                                                    error(
                                                        "TRYAGAIN upstream response could not be sanitized",
                                                    )
                                                })
                                        }
                                        ResponsePolicy::StreamRead => {
                                            sanitize_stream_read(&response, tenant).unwrap_or_else(
                                                |sanitize_error| {
                                                    state.metrics.upstream_failed();
                                                    tracing::warn!(%sanitize_error, tenant = tenant.id(), "upstream stream response was invalid");
                                                    error(
                                                        "TRYAGAIN upstream response could not be sanitized",
                                                    )
                                                },
                                            )
                                        }
                                    },
                                    Err(upstream_error) => {
                                        state.metrics.upstream_failed();
                                        tracing::warn!(%upstream_error, tenant = tenant.id(), "upstream request failed");
                                        error("TRYAGAIN upstream request failed")
                                    }
                                }
                            }
                        }
                    }
                },
            },
            Err(message) => {
                state.metrics.rejected();
                error(message)
            }
        };
        send(writer, &response, &state.metrics).await?;
    }
}

fn authenticate(
    arguments: &[Bytes],
    tenants: &TenantRegistry,
    current: &mut Option<Arc<Tenant>>,
    metrics: &Metrics,
) -> Vec<u8> {
    let (username, password) = match arguments {
        [_, password] => (None, password.as_ref()),
        [_, username, password] => (Some(username.as_ref()), password.as_ref()),
        _ => return error("ERR wrong number of arguments for 'auth' command"),
    };
    match tenants.authenticate(username, password) {
        Some(tenant) => {
            *current = Some(tenant);
            metrics.authenticated();
            simple("OK")
        }
        None => {
            metrics.authentication_failed();
            error("WRONGPASS invalid username-password pair or user is disabled.")
        }
    }
}

fn hello(
    arguments: &[Bytes],
    tenants: &TenantRegistry,
    current: &mut Option<Arc<Tenant>>,
    metrics: &Metrics,
    cluster: bool,
) -> Vec<u8> {
    let protocol = match arguments.get(1).map(Bytes::as_ref) {
        None => 2,
        Some(b"2") => 2,
        Some(b"3") => 3,
        _ => return error("NOPROTO unsupported protocol version"),
    };
    let mut index = if arguments.len() == 1 { 1 } else { 2 };
    let mut auth = None;
    while index < arguments.len() {
        if ascii_eq(&arguments[index], b"AUTH") {
            if index + 2 >= arguments.len() || auth.is_some() {
                return error("ERR syntax error");
            }
            auth = Some((arguments[index + 1].as_ref(), arguments[index + 2].as_ref()));
            index += 3;
        } else if ascii_eq(&arguments[index], b"SETNAME") {
            if index + 1 >= arguments.len() {
                return error("ERR syntax error");
            }
            index += 2;
        } else {
            return error("ERR syntax error");
        }
    }

    if let Some((username, password)) = auth {
        match tenants.authenticate(Some(username), password) {
            Some(tenant) => {
                *current = Some(tenant);
                metrics.authenticated();
            }
            None => {
                metrics.authentication_failed();
                return error("WRONGPASS invalid username-password pair or user is disabled.");
            }
        }
    } else if current.is_none() {
        return error("NOAUTH Authentication required.");
    }

    hello_response(protocol, if cluster { "cluster" } else { "standalone" })
}

fn hello_response(protocol: u8, mode: &str) -> Vec<u8> {
    if protocol == 3 {
        return format!(
            "%7\r\n+server\r\n+rproxy\r\n+version\r\n+{}\r\n+proto\r\n:{}\r\n+id\r\n:0\r\n+mode\r\n+{}\r\n+role\r\n+master\r\n+modules\r\n*0\r\n",
            env!("CARGO_PKG_VERSION"),
            protocol,
            mode
        )
        .into_bytes();
    }

    let mut response = b"*14\r\n".to_vec();
    append_hello_bulk(&mut response, b"server");
    append_hello_bulk(&mut response, b"rproxy");
    append_hello_bulk(&mut response, b"version");
    append_hello_bulk(&mut response, env!("CARGO_PKG_VERSION").as_bytes());
    append_hello_bulk(&mut response, b"proto");
    response.extend_from_slice(format!(":{protocol}\r\n").as_bytes());
    append_hello_bulk(&mut response, b"id");
    response.extend_from_slice(b":0\r\n");
    append_hello_bulk(&mut response, b"mode");
    append_hello_bulk(&mut response, mode.as_bytes());
    append_hello_bulk(&mut response, b"role");
    append_hello_bulk(&mut response, b"master");
    append_hello_bulk(&mut response, b"modules");
    response.extend_from_slice(b"*0\r\n");
    response
}

fn append_hello_bulk(response: &mut Vec<u8>, value: &[u8]) {
    response.extend_from_slice(format!("${}\r\n", value.len()).as_bytes());
    response.extend_from_slice(value);
    response.extend_from_slice(b"\r\n");
}

fn command_payload_bytes(command: &crate::protocol::Command) -> usize {
    command.args.iter().fold(0usize, |total, argument| {
        total.saturating_add(argument.len())
    })
}

fn encode_transaction(
    commands: &[crate::protocol::Command],
    tenant: &Tenant,
    require_single_slot: bool,
) -> Result<(Option<u16>, Vec<Vec<u8>>), &'static str> {
    let mut transaction_slot = None;
    let mut requests = Vec::with_capacity(commands.len());
    for command in commands {
        let Ok(Plan::Forward {
            keys,
            key_mode: KeyMode::Literal,
            response: ResponsePolicy::Raw,
        }) = plan(command)
        else {
            return Err("ERR command is not supported inside a phase 2 transaction");
        };
        let indices = key_indices(command, keys)?;
        if require_single_slot {
            let slot = slot_for_keys(tenant, command, &indices)?;
            match transaction_slot {
                Some(previous) if previous != slot => {
                    return Err("CROSSSLOT Keys in request don't hash to the same slot");
                }
                None => transaction_slot = Some(slot),
                _ => {}
            }
        }
        let rewritten = rewrite(command, &indices, |key| tenant.rewrite_key(key));
        requests.push(encode_command(&rewritten));
    }
    Ok((transaction_slot, requests))
}

fn slot_for_keys(
    tenant: &Tenant,
    command: &crate::protocol::Command,
    key_indices: &[usize],
) -> Result<u16, &'static str> {
    let Some((first, rest)) = key_indices.split_first() else {
        return Err("ERR command has no routable key");
    };
    let slot = tenant.slot_for_key(&command.args[*first]);
    if rest
        .iter()
        .any(|index| tenant.slot_for_key(&command.args[*index]) != slot)
    {
        return Err("CROSSSLOT Keys in request don't hash to the same slot");
    }
    Ok(slot)
}

fn rewrite_scan(
    command: &crate::protocol::Command,
    tenant: &Tenant,
) -> Result<Vec<Bytes>, &'static str> {
    if command.args.len() < 2 {
        return Err("ERR wrong number of arguments for 'scan' command");
    }
    let mut arguments = command.args.clone();
    let mut index = 2;
    let mut match_index = None;
    while index < arguments.len() {
        if ascii_eq(&arguments[index], b"MATCH") {
            if index + 1 == arguments.len() {
                return Err("ERR syntax error");
            }
            if match_index.replace(index + 1).is_some() {
                return Err("ERR syntax error");
            }
            index += 2;
        } else if ascii_eq(&arguments[index], b"COUNT") || ascii_eq(&arguments[index], b"TYPE") {
            if index + 1 == arguments.len() {
                return Err("ERR syntax error");
            }
            index += 2;
        } else {
            return Err("ERR syntax error");
        }
    }

    match match_index {
        Some(index) => arguments[index] = tenant.rewrite_pattern(&arguments[index]),
        None => {
            arguments.push(Bytes::from_static(b"MATCH"));
            arguments.push(tenant.rewrite_pattern(b"*"));
        }
    }
    Ok(arguments)
}

fn ascii_eq(value: &[u8], expected: &[u8]) -> bool {
    value.eq_ignore_ascii_case(expected)
}

fn require_tenant(tenant: &Option<Arc<Tenant>>) -> Result<(), &'static str> {
    tenant
        .is_some()
        .then_some(())
        .ok_or("NOAUTH Authentication required.")
}

async fn send(writer: &mut OwnedWriteHalf, response: &[u8], metrics: &Metrics) -> Result<()> {
    writer.write_all(response).await?;
    metrics.sent_bytes(response.len() as u64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            LimitsConfig, ListenerConfig, ObservabilityConfig, TenantConfig, UpstreamConfig,
            UpstreamKind,
        },
        protocol::{Command, encode_command, read_command, read_frame},
    };
    use tokio::{
        io::{AsyncWriteExt, BufReader},
        net::TcpListener,
        sync::oneshot,
    };

    fn test_config(upstream_address: String) -> Config {
        Config {
            schema_version: 1,
            listener: ListenerConfig {
                address: "127.0.0.1:0".to_owned(),
            },
            upstream: UpstreamConfig {
                kind: UpstreamKind::Standalone,
                bootstrap_endpoints: Vec::new(),
                address: upstream_address,
                username: None,
                password: None,
            },
            tenants: vec![TenantConfig {
                id: "payments".to_owned(),
                username: None,
                password: "tenant-secret".to_owned(),
                partition_count: 256,
            }],
            limits: LimitsConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }

    #[tokio::test]
    async fn authenticates_and_rewrites_a_pipelined_single_key_request() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap().to_string();
        let (key_sender, key_receiver) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let request = read_command(&mut reader, 4096).await.unwrap().unwrap();
            key_sender.send(request.args[1].to_vec()).unwrap();
            writer.write_all(b"+OK\r\n").await.unwrap();
        });

        let state = Arc::new(AppState::from_config(&test_config(upstream_address)));
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_connection(stream, state).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        let auth = encode_command(&[
            Bytes::from_static(b"AUTH"),
            Bytes::from_static(b"tenant-secret"),
        ]);
        let set = encode_command(&[
            Bytes::from_static(b"SET"),
            Bytes::from_static(b"cart:42"),
            Bytes::from_static(b"active"),
        ]);
        client.write_all(&auth).await.unwrap();
        client.write_all(&set).await.unwrap();

        let mut client_reader = BufReader::new(client);
        assert_eq!(
            read_frame(&mut client_reader, 4096).await.unwrap().unwrap(),
            b"+OK\r\n"
        );
        assert_eq!(
            read_frame(&mut client_reader, 4096).await.unwrap().unwrap(),
            b"+OK\r\n"
        );
        let physical_key = key_receiver.await.unwrap();
        assert!(physical_key.starts_with(b"__rproxy:v1:{t/payments/d/0/p/"));
        assert!(physical_key.ends_with(b"}:cart:42"));

        drop(client_reader);
        proxy_task.await.unwrap();
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn bounds_transaction_queue_by_configured_pipeline_depth() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config(upstream_listener.local_addr().unwrap().to_string());
        config.limits.max_pipeline_depth = 1;
        let state = Arc::new(AppState::from_config(&config));
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_connection(stream, state).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        let auth = encode_command(&[
            Bytes::from_static(b"AUTH"),
            Bytes::from_static(b"tenant-secret"),
        ]);
        let multi = encode_command(&[Bytes::from_static(b"MULTI")]);
        let set = encode_command(&[
            Bytes::from_static(b"SET"),
            Bytes::from_static(b"cart:42"),
            Bytes::from_static(b"active"),
        ]);
        client
            .write_all(&[auth, multi, set.clone(), set].concat())
            .await
            .unwrap();

        let mut client_reader = BufReader::new(client);
        assert_eq!(
            read_frame(&mut client_reader, 4096).await.unwrap().unwrap(),
            b"+OK\r\n"
        );
        assert_eq!(
            read_frame(&mut client_reader, 4096).await.unwrap().unwrap(),
            b"+OK\r\n"
        );
        assert_eq!(
            read_frame(&mut client_reader, 4096).await.unwrap().unwrap(),
            b"+QUEUED\r\n"
        );
        assert_eq!(
            read_frame(&mut client_reader, 4096).await.unwrap().unwrap(),
            b"-ERR transaction queue limit exceeded\r\n"
        );

        drop(client_reader);
        proxy_task.await.unwrap();
    }

    #[test]
    fn validates_cluster_slots_before_forwarding_multi_key_requests() {
        let registry = TenantRegistry::new(&[TenantConfig {
            id: "payments".to_owned(),
            username: None,
            password: "tenant-secret".to_owned(),
            partition_count: 256,
        }]);
        let tenant = registry.authenticate(None, b"tenant-secret").unwrap();
        let colocated = Command {
            args: vec![
                Bytes::from_static(b"MGET"),
                Bytes::from_static(b"{order:42}:total"),
                Bytes::from_static(b"{order:42}:status"),
            ],
        };
        assert!(slot_for_keys(&tenant, &colocated, &[1, 2]).is_ok());

        let first = Bytes::from_static(b"{customer:1}:profile");
        let first_slot = tenant.slot_for_key(&first);
        let second = (0..1024)
            .map(|index| Bytes::from(format!("{{customer:{index}}}:profile")))
            .find(|key| tenant.slot_for_key(key) != first_slot)
            .expect("test inputs must span at least two partitions");
        let cross_slot = Command {
            args: vec![Bytes::from_static(b"MGET"), first, second],
        };
        assert_eq!(
            slot_for_keys(&tenant, &cross_slot, &[1, 2]),
            Err("CROSSSLOT Keys in request don't hash to the same slot")
        );
    }

    #[test]
    fn hello_authenticates_and_returns_a_resp3_handshake() {
        let registry = TenantRegistry::new(&[TenantConfig {
            id: "payments".to_owned(),
            username: Some("app".to_owned()),
            password: "tenant-secret".to_owned(),
            partition_count: 256,
        }]);
        let mut tenant = None;
        let response = hello(
            &[
                Bytes::from_static(b"HELLO"),
                Bytes::from_static(b"3"),
                Bytes::from_static(b"AUTH"),
                Bytes::from_static(b"app"),
                Bytes::from_static(b"tenant-secret"),
            ],
            &registry,
            &mut tenant,
            &Metrics::default(),
            false,
        );
        assert!(tenant.is_some());
        assert!(response.starts_with(b"%7\r\n+server\r\n+rproxy\r\n"));
        assert!(
            response
                .windows(b"+proto\r\n:3\r\n".len())
                .any(|part| part == b"+proto\r\n:3\r\n")
        );
    }

    #[tokio::test]
    async fn closes_an_idle_client_at_the_configured_timeout() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = test_config(upstream_listener.local_addr().unwrap().to_string());
        config.limits.client_idle_timeout_ms = 1;
        let state = Arc::new(AppState::from_config(&config));
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_connection(stream, state).await.unwrap();
        });

        let _client = TcpStream::connect(proxy_address).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), proxy_task)
            .await
            .expect("idle connection must close")
            .unwrap();
    }
}
