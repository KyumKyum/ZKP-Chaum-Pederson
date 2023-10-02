FROM rust:1.70

WORKDIR /zkp-serv

COPY . .

RUN apt-get update && apt-get install -y protobuf-compiler
RUN cargo build  --release --bin server --bin client