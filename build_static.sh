#!/bin/bash
set -e

# Name of the resulting binary
OUTPUT_BIN="sutatikku"

echo "Building static Sutatikku using Docker (Alpine/musl)..."

# Build the Docker image
docker build -t sutatikku-builder .

# Create a temporary container to extract the binary
CONTAINER_ID=$(docker create sutatikku-builder)

# Copy the binary from the container to the local filesystem
docker cp "${CONTAINER_ID}:/sutatikku" "./${OUTPUT_BIN}"

# Remove the temporary container
docker rm "${CONTAINER_ID}"

echo "----------------------------------------------------"
echo "Success! Static binary created: ./${OUTPUT_BIN}"
ls -lh "./${OUTPUT_BIN}"
file "./${OUTPUT_BIN}"
if command -v ldd >/dev/null; then
    echo "Verification (ldd):"
    ldd "./${OUTPUT_BIN}" || echo " (Note: ldd might report an error for static binaries on some systems, which is normal)"
fi
