# Multi-stage build for S1AP Analyzer
# Stage 1: Build environment
FROM golang:1.22-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    libc6-dev \
    libpcap-dev \
    pkg-config \
    make \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
COPY testdata/s1CP.pcap /app/data/s1CP.pcap
# Download dependencies
RUN go mod download

# Copy source code
COPY . .

    # Build the ASN.1 library first
    WORKDIR /app/pkg/s1ap/asn1
    # Remove the problematic converter-example.c file before building
    RUN rm -f converter-example.c && \
        gcc -I. -c *.c && \
        ar -rc libs1ap.a *.o && \
        ar -rc libasn1c.a *.o && \
        cp libs1ap.a /usr/local/lib/ && \
        cp libasn1c.a /usr/local/lib/
    
    # Go back to main directory and build the application
WORKDIR /app
ENV CGO_ENABLED=1
RUN go build -o s1ap-analyzer ./cmd/s1ap-analyzer/

# Stage 2: Runtime environment
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    ca-certificates \
    tzdata \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the built binary
COPY --from=builder /app/s1ap-analyzer .

# Copy additional files
COPY --from=builder /app/mcc-mnc-table.json ./mcc-mnc-table.json

# Create directories for output
RUN mkdir -p /app/output /app/data

# Run as root for network access (required for Kubernetes)
USER root

# Flexible entrypoint for Kubernetes
ENTRYPOINT ["./s1ap-analyzer"]
CMD ["-help"]