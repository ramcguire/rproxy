use std::{
    io,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Default)]
pub struct Metrics {
    accepted_connections: AtomicU64,
    active_connections: AtomicU64,
    authenticated_connections: AtomicU64,
    authentication_failures: AtomicU64,
    requests: AtomicU64,
    rejected_requests: AtomicU64,
    upstream_failures: AtomicU64,
    bytes_from_clients: AtomicU64,
    bytes_to_clients: AtomicU64,
}

impl Metrics {
    pub fn accepted_connection(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn closed_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn authenticated(&self) {
        self.authenticated_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn authentication_failed(&self) {
        self.authentication_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rejected(&self) {
        self.rejected_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn upstream_failed(&self) {
        self.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn received_bytes(&self, count: u64) {
        self.bytes_from_clients.fetch_add(count, Ordering::Relaxed);
    }

    pub fn sent_bytes(&self, count: u64) {
        self.bytes_to_clients.fetch_add(count, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let mut output = String::new();
        for (name, value) in [
            (
                "rproxy_connections_accepted_total",
                self.accepted_connections.load(Ordering::Relaxed),
            ),
            (
                "rproxy_connections_active",
                self.active_connections.load(Ordering::Relaxed),
            ),
            (
                "rproxy_connections_authenticated_total",
                self.authenticated_connections.load(Ordering::Relaxed),
            ),
            (
                "rproxy_authentication_failures_total",
                self.authentication_failures.load(Ordering::Relaxed),
            ),
            (
                "rproxy_requests_total",
                self.requests.load(Ordering::Relaxed),
            ),
            (
                "rproxy_requests_rejected_total",
                self.rejected_requests.load(Ordering::Relaxed),
            ),
            (
                "rproxy_upstream_failures_total",
                self.upstream_failures.load(Ordering::Relaxed),
            ),
            (
                "rproxy_client_bytes_received_total",
                self.bytes_from_clients.load(Ordering::Relaxed),
            ),
            (
                "rproxy_client_bytes_sent_total",
                self.bytes_to_clients.load(Ordering::Relaxed),
            ),
        ] {
            output.push_str(name);
            output.push(' ');
            output.push_str(&value.to_string());
            output.push('\n');
        }
        output
    }
}

pub async fn serve_http(listener: TcpListener, metrics: Arc<Metrics>) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(error) = handle_http(stream, metrics).await {
                tracing::debug!(%error, "metrics request failed");
            }
        });
    }
}

async fn handle_http(mut stream: TcpStream, metrics: Arc<Metrics>) -> io::Result<()> {
    let mut request = [0; 1024];
    let count = stream.read(&mut request).await?;
    let target = request[..count]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let (status, content_type, body) = if target.starts_with(b"GET /healthz ") {
        ("200 OK", "text/plain", "ok\n".to_owned())
    } else if target.starts_with(b"GET /readyz ") {
        ("200 OK", "text/plain", "ready\n".to_owned())
    } else if target.starts_with(b"GET /metrics ") {
        ("200 OK", "text/plain; version=0.0.4", metrics.render())
    } else {
        ("404 Not Found", "text/plain", "not found\n".to_owned())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_prometheus_lines() {
        let metrics = Metrics::default();
        metrics.request();
        assert!(metrics.render().contains("rproxy_requests_total 1\n"));
    }
}
