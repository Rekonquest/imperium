# Cloakwise — multi-stage release image
FROM rust:bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY configs ./configs
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/cloakwise /usr/local/bin/cloakwise
COPY configs/default.yaml /etc/cloakwise/config.yaml
ENV RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cloakwise"]
CMD ["-c", "/etc/cloakwise/config.yaml"]
