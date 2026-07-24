# syntax=docker/dockerfile:1.7

FROM rust:1.97-bookworm AS builder
WORKDIR /app

# Copy manifests first so dependency resolution remains cached while application
# sources change. BuildKit cache mounts retain Cargo downloads and compilation
# outputs between builds without placing them in the final image.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && printf 'fn main() {}\n' > src/main.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked

COPY src/ ./src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    touch src/main.rs \
    && cargo build --release --locked \
    && install -D -m 0755 target/release/rproxy /out/rproxy

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

COPY --from=builder --chown=nonroot:nonroot /out/rproxy /usr/local/bin/rproxy

USER nonroot:nonroot
EXPOSE 6379 9090
ENTRYPOINT ["/usr/local/bin/rproxy"]
