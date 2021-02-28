FROM rust:1.50.0 AS builder

WORKDIR /usr/src/vault-sync
COPY . .
RUN cargo install --path .

FROM debian:buster-slim
COPY --from=builder /usr/local/cargo/bin/vault-sync /usr/local/bin/vault-sync
CMD ["vault-sync"]
