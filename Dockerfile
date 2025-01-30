# Use the Alpine-based Rust image as builder
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev gcc
WORKDIR /usr/src/paperback
COPY . .
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

FROM alpine:3 AS runner
RUN apk add --no-cache libgcc
COPY --from=builder /usr/src/paperback/target/release/paperback /usr/local/bin/
RUN chmod +x /usr/local/bin/paperback

WORKDIR /data
ENTRYPOINT ["paperback"]