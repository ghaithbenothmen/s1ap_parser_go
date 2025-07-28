# CoreSwitch S1AP Analyzer

A professional, high-performance S1AP (S1 Application Protocol) analyzer for PCAP files. This tool provides comprehensive analysis of S1AP messages used in LTE/4G networks between eNodeB and MME, with advanced MongoDB session storage capabilities.

## Features

- **Comprehensive S1AP Support**: Analyzes all 67 S1AP procedure types
- **Multiple Output Formats**: Simple, detailed, and JSON output formats
- **MongoDB Session Storage**: Real-time storage and analysis of UE sessions
- **Session Management**: Track complete UE session lifecycles based on eNB-UE-S1AP-ID
- **High Performance**: Optimized for large PCAP files with packet limiting
- **Professional CLI**: Clean command-line interface with extensive options
- **Accurate Parsing**: Real procedure code extraction from ASN.1 APER encoding
- **Statistics**: Detailed analysis statistics and procedure breakdowns
- **Session Query Tools**: Advanced MongoDB querying and analysis tools
- **Cross-Platform**: Builds for Linux, macOS, and Windows

## Supported S1AP Procedures

The analyzer supports all standard S1AP procedures including:
- Paging, Initial UE Message, UL/DL NAS Transport
- Handover procedures, E-RAB management
- UE Context operations, Status transfers
- Configuration updates, Error handling
- And many more...

## MongoDB Session Storage

The analyzer now includes advanced MongoDB integration for real-time session storage:

- **Real-time Storage**: S1AP messages are stored in MongoDB during decoding
- **UE Session Tracking**: Messages are organized by UE sessions using eNB-UE-S1AP-ID
- **Session Evolution**: Automatic updates when new messages arrive for existing sessions
- **Lifecycle Management**: Track session creation, evolution, and termination
- **Advanced Querying**: Powerful tools to search and analyze stored sessions

### Key Benefits

- **Session Correlation**: All messages from the same UE are grouped together
- **Time-series Analysis**: Track UE behavior over time
- **Scalable Storage**: Handle large volumes of S1AP traffic
- **Flexible Queries**: Search by eNB, MME, procedure type, time ranges
- **Real-time Processing**: No need to wait for complete analysis

## Installation

### Prerequisites

- Go 1.19 or later
- libpcap development libraries
- ASN.1 C libraries (included)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/coreswitch/coreswitch.git
cd coreswitch

# Build the application
make build

# Install system-wide (optional)
make install
```

### Development Setup

```bash
# Complete development environment setup
make dev-setup
```

## Usage

### Basic Usage

```bash
# Analyze a PCAP file
./build/s1ap-analyzer capture.pcap

# Show statistics only
./build/s1ap-analyzer -stats capture.pcap

# Limit analysis to first 1000 packets
./build/s1ap-analyzer -limit 1000 capture.pcap
```

### Advanced Usage

```bash
# Detailed output format
./build/s1ap-analyzer -format detailed capture.pcap

# JSON output for programmatic processing
./build/s1ap-analyzer -format json capture.pcap > analysis.json

# Debug mode for troubleshooting
./build/s1ap-analyzer -debug capture.pcap

# Show help
./build/s1ap-analyzer -help
```

### MongoDB Session Storage

```bash
# Analyze and store sessions in MongoDB
./build/s1ap-analyzer -mongo-store capture.pcap

# Custom MongoDB configuration
./build/s1ap-analyzer \
  -mongo-store \
  -mongo-uri "mongodb://localhost:27017" \
  -mongo-db "s1ap_analysis" \
  -mongo-collection "ue_sessions" \
  capture.pcap

# Real-time analysis with debug output
./build/s1ap-analyzer -mongo-store -debug -limit 1000 capture.pcap
```

### Session Querying

```bash
# Build the session query tool
make build-session-query

# List all active sessions
./build/session-query -command list -status active

# Find sessions for specific eNB
./build/session-query -command find -enb-id 123

# Show global statistics
./build/session-query -command stats

# Top procedures for an eNB
./build/session-query -command procedures -enb-id 123

# Export sessions to JSON
./build/session-query -command list -format json > sessions.json
```

### Output Formats

#### Simple Format (Default)
```
2025/07/23 10:48:48 PDU type: InitiatingMessage
2025/07/23 10:48:48 Message type: Paging
packet_number: 4
timestamp: 1737102645.014235
timestamp_human: 2025-01-17 09:30:45.014
src_ip: 10.3.3.112
dst_ip: 10.73.100.58
s1ap_pdu:
  type: initiatingMessage
  type_code: 0
procedure:
  name: Paging
  code: 10
  criticality: ignore
```

#### JSON Format
```json
{
  "messages": [
    {
      "packet_number": 4,
      "timestamp": "2025-01-17T09:30:45.014235Z",
      "src_ip": "10.3.3.112",
      "dst_ip": "10.73.100.58",
      "pdu_type": "initiatingMessage",
      "pdu_type_code": 0,
      "procedure_name": "Paging",
      "procedure_code": 10,
      "criticality": "ignore"
    }
  ],
  "statistics": {
    "total_frames": 1000,
    "s1ap_frames": 245,
    "successful_decodes": 220,
    "procedure_stats": {
      "Paging": 154,
      "downlinkNASTransport": 22,
      "CellTrafficTrace": 18
    }
  }
}
```

## Architecture

The project follows a clean, modular architecture:

```
coreswitch/
├── cmd/
│   └── s1ap-analyzer/     # Main application
├── pkg/
│   ├── s1ap/              # S1AP protocol library
│   ├── hss/               # HSS server components
│   └── mme/               # MME server components
├── tools/                 # Development tools
├── examples/              # Usage examples
├── docs/                  # Documentation
├── testdata/              # Test PCAP files
└── build/                 # Build outputs
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Lint code
make lint
```

## Development

### Building

```bash
# Development build with race detector
make dev

# Build for multiple platforms
make build-all

# Clean build artifacts
make clean
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Full development workflow
make dev-setup
```

## Performance

The analyzer is optimized for performance:
- **Memory Efficient**: Streams PCAP data without loading entire file
- **Fast Processing**: Optimized S1AP parsing with minimal allocations
- **Scalable**: Handles large PCAP files (GB+) efficiently
- **Configurable**: Packet limiting for quick analysis

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `make test`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Development Guidelines

- Follow Go best practices and conventions
- Add tests for new functionality
- Update documentation for user-facing changes
- Run `make lint` before submitting


## Acknowledgments

- ASN.1 C libraries for S1AP protocol support
- GoPacket library for PCAP processing
- The telecommunications community for S1AP specifications

## Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Check the documentation in `docs/`
- Review examples in `examples/`

---

**Professional S1AP Analysis Made Simple** 

----

coreswitch is an open soruce project for EPC (Evolved Packet Core) of LTE and 5G
infrastructure. Right now we are implementing MME (Mobility Management Entity).
Other component will be implemented later on.

----

## Supported Platform

Right now only Ubuntu 18.04 is supported.

## Build

To build the system.  ASN1 handling C library needs to be built.

``` shell
$ cd coreswitch/pkg/s1ap/asn1
$ make lib
$ sudo make install
```

After this

``` shell
$ go get github.com/coreswitch/coreswitch/cmd/mmed
```

will build mmed.

## Run

Just simply execute `mmed` will start MME handling on all of interfaces.

``` shell
$ mmed
2019/08/28 14:21:42 Listen on 127.0.0.1/[::1%lo]/10.211.55.26/[fe80::38e7:5a76:4355:51d7%enp0s5]/[fe80::79d1:506d:7682:9ee5%enp0s6]/[fe80::cd97:63f4:fcad:b2c5%enp0s7]/172.18.0.1/172.17.0.1:36412

```
