FROM rust:1.92-alpine AS chef
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig make perl git cmake clang build-base
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
ENV OPENSSL_STATIC=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/mavewaf /app/mavewaf-bin

FROM alpine:3.23.2 AS runtime
RUN apk add --no-cache tor i2pd ca-certificates su-exec
RUN addgroup -S mavewaf && adduser -S mavewaf -G mavewaf
WORKDIR /app
COPY --from=builder /app/mavewaf-bin /app/mavewaf
COPY --from=builder /app/templates /app/templates
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN apk del apk-tools && rm -rf /var/cache/apk/* /lib/apk /usr/share/apk
EXPOSE 8080 8081
ENTRYPOINT ["/entrypoint.sh"]
