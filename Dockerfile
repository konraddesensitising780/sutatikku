FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    libseccomp-dev \
    libseccomp-static \
    gcc \
    make \
    pkgconfig

WORKDIR /usr/src/sutatikku

# Copy the source code
COPY . .

# Build the project statically
# We use the musl target and force crt-static
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl

# Use a minimal image to verify the binary or just extract it
FROM scratch
COPY --from=builder /usr/src/sutatikku/target/x86_64-unknown-linux-musl/release/sutatikku /sutatikku
ENTRYPOINT ["/sutatikku"]
