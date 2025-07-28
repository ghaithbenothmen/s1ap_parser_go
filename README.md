# CoreSwitch S1AP Protocol Suite

A professional, unified S1AP protocol analysis and management suite for 3GPP core network components.

## Overview

CoreSwitch provides comprehensive tools for:
- **S1AP Protocol Analysis**: Analyze S1AP messages from PCAP files with detailed statistics
- **Session Management**: Query and manage UE sessions with MongoDB storage
- **Core Network Components**: MME and HSS server implementations
- **Professional Logging**: Structured, configurable logging system

## Features

### 🔍 S1AP Protocol Analyzer
- Parse and analyze S1AP messages from PCAP files
- Support for multiple output formats (simple, detailed, JSON)
- Real-time session tracking and MongoDB storage
- Comprehensive procedure statistics
- Professional logging with configurable levels

### 📊 Session Query Engine
- Query UE sessions by various criteria (eNB ID, MME ID, status)
- Global session statistics and analytics
- Top procedure analysis per eNB
- Multiple output formats (table, JSON, summary)

### 🏗️ Core Network Servers
- **MME**: Mobility Management Entity implementation
- **HSS**: Home Subscriber Server implementation
- Production-ready server components

### 📝 Professional Architecture
- Unified command-line interface
- Modular, maintainable codebase
- Comprehensive error handling
- Clean, professional logging (no emojis)
- Extensible configuration system

## Installation

### Prerequisites
- Go 1.19 or later
- MongoDB (for session storage)
- libpcap development headers

### Build from Source

```bash
# Clone the repository
git clone https://github.com/ghaithbenothmen/coreswitch.git
cd coreswitch

# Install dependencies
make deps

# Build the application
make build

# Install system-wide (optional)
make install
```

### Development Setup

```bash
# Complete development environment setup
make deps format check test build

# Run tests with coverage
make test-coverage

# Development build with debug symbols
make dev
```

## Usage

### S1AP Protocol Analysis

```bash
# Basic analysis
coreswitch s1ap-analyzer capture.pcap

# Detailed analysis with JSON output
coreswitch s1ap-analyzer -format json -limit 1000 capture.pcap

# Store sessions in MongoDB
coreswitch s1ap-analyzer -mongo-store -debug capture.pcap

# Custom MongoDB configuration
coreswitch s1ap-analyzer \
  -mongo-store \
  -mongo-uri "mongodb://localhost:27017" \
  -mongo-db "s1ap_analysis" \
  -mongo-collection "ue_sessions" \
  capture.pcap

# Statistics only
coreswitch s1ap-analyzer -stats capture.pcap
```

### Session Querying

```bash
# List all active sessions
coreswitch session-query -command list -status active

# Find sessions for specific eNB
coreswitch session-query -command find -enb-id 123

# Show global statistics
coreswitch session-query -command stats

# Top procedures for an eNB
coreswitch session-query -command procedures -enb-id 123

# Export sessions to JSON
coreswitch session-query -command list -format json > sessions.json
```

### Core Network Servers

```bash
# Start MME server
coreswitch mme -debug -port 3868

# Start HSS server
coreswitch hss -verbose -port 3869
```

### Global Options

All commands support these global options:
- `-debug`: Enable debug logging
- `-verbose`: Enable verbose logging with caller information
- `-log-level`: Set log level (DEBUG, INFO, WARN, ERROR, FATAL)

## Configuration

### MongoDB Configuration
- **URI**: Connection string (default: `mongodb://10.200.0.21:27017`)
- **Database**: Database name (default: `s1ap_db`)
- **Collection**: Collection name (default: `messages`)

### Output Formats

#### S1AP Analyzer
- **simple**: Human-readable YAML-like format
- **detailed**: Enhanced simple format with additional information
- **json**: Structured JSON output

#### Session Query
- **table**: Formatted table view
- **json**: Structured JSON output
- **summary**: Condensed statistics view

## API Reference

### Command Structure

```
coreswitch <command> [global-options] [command-options]
```

### Commands

#### `s1ap-analyzer`
Analyze S1AP messages from PCAP files.

**Options:**
- `-format string`: Output format (simple, detailed, json)
- `-limit int`: Limit number of packets to analyze
- `-stats`: Show statistics summary only
- `-mongo-store`: Enable MongoDB storage
- `-mongo-uri string`: MongoDB connection URI
- `-mongo-db string`: MongoDB database name
- `-mongo-collection string`: MongoDB collection name

#### `session-query`
Query S1AP sessions from MongoDB.

**Options:**
- `-command string`: Command to execute (list, find, stats, procedures)
- `-enb-id string`: eNB ID for filtering
- `-mme-id string`: MME ID for filtering
- `-status string`: Session status filter (active, released)
- `-format string`: Output format (table, json, summary)
- `-limit int`: Limit number of results

#### `mme`
Start MME server.

**Options:**
- `-listen string`: Listen address (default: 0.0.0.0)
- `-port int`: Listen port (default: 8080)

#### `hss`
Start HSS server.

**Options:**
- `-listen string`: Listen address (default: 0.0.0.0)
- `-port int`: Listen port (default: 8080)

## Architecture

### Project Structure

```
├── main.go                 # Unified entry point
├── pkg/
│   ├── analyzer/          # S1AP analysis engine
│   ├── config/            # Configuration management
│   ├── logger/            # Professional logging system
│   ├── sessionquery/      # Session query service
│   ├── db/               # Database utilities
│   ├── s1ap/             # S1AP protocol implementation
│   ├── mme/              # MME server
│   └── hss/              # HSS server
├── build/                # Build artifacts
└── docs/                 # Documentation
```

### Key Components

- **Unified CLI**: Single entry point with subcommands
- **Modular Architecture**: Clean separation of concerns
- **Professional Logging**: Structured, configurable logging
- **Configuration Management**: Centralized configuration system
- **Error Handling**: Comprehensive error handling and validation

## Development

### Makefile Targets

```bash
make help          # Show all available targets
make build         # Build the application
make test          # Run tests
make format        # Format code
make check         # Run code quality checks
make lint          # Run linter (requires golangci-lint)
make clean         # Clean build artifacts
make release       # Build for multiple platforms
```

### Code Quality

The project maintains high code quality standards:
- Go formatting with `gofmt`
- Static analysis with `go vet`
- Linting with `golangci-lint`
- Comprehensive test coverage
- Professional error handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Format code: `make format`
6. Run checks: `make check`
7. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation in the `docs/` directory
- Review the examples and usage patterns

---

**CoreSwitch** - Professional S1AP Protocol Suite
