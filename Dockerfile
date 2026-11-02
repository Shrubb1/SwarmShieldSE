# snn-firewall http_shield — one-binary WAF gate.
#   docker build -t snn-shield .
#   docker run -d -p 8081:8081 snn-shield 0.0.0.0:8081
FROM rust:1.83-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release --bin http_shield

FROM debian:bookworm-slim
RUN useradd -r -u 10001 shield
COPY --from=build /src/target/release/http_shield /usr/local/bin/
USER shield
EXPOSE 8081
# arg: listen addr (default 127.0.0.1:8081 inside the binary)
ENTRYPOINT ["http_shield"]
CMD ["0.0.0.0:8081"]
