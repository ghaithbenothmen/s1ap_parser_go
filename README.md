# S1AP Protocol Analyzer

A high-performance S1AP (S1 Application Protocol) analyzer for LTE/4G network monitoring. Analyzes S1AP signaling messages between eNodeB and MME with MongoDB session storage support.

## Features

- **Protocol Support**: All 67 S1AP procedure types
- **Multiple Outputs**: Simple, JSON, and detailed formats  
- **Session Tracking**: MongoDB integration for UE session storage
- **Live Capture**: Real-time network interface monitoring
- **High Performance**: Optimized for large PCAP files

## Installation

### Prerequisites
- Go 1.22 or higher
- MongoDB 4.4+ (optional, for session storage)
- libpcap development libraries

### Build
```bash
# Clone and build
git clone <repository-url>
cd coreswitch

# Build ASN.1 libraries
cd pkg/s1ap/asn1 && make lib && sudo make install

# Build application
cd ../../../ && make build
```

## Usage

### Basic Commands
```bash
# Analyze PCAP file
./build/s1ap-analyzer capture.pcap

# JSON output
./build/s1ap-analyzer -format json capture.pcap

# Statistics only
./build/s1ap-analyzer -stats capture.pcap

# Live capture
./build/s1ap-analyzer -interface eth0 -duration 60s

# MongoDB storage
./build/s1ap-analyzer -mongo-store capture.pcap
```

### Common Options
- `-format`: Output format (simple, detailed, json)
- `-limit`: Limit number of packets
- `-debug`: Enable debug output
- `-mongo-store`: Store sessions in MongoDB
- `-interface`: Network interface for live capture

## Output Examples

### Simple Format
```
packet_number: 1
timestamp: 2025-01-17 09:30:45.014
src_ip: 10.3.3.112
dst_ip: 10.73.100.58
procedure:
  name: Paging
  code: 10
```

### JSON Format  
```json
{
  "messages": [
    {
      "packet_number": 1,
      "timestamp": "2025-01-17T09:30:45.014Z",
      "procedure_name": "Paging",
      "src_ip": "10.3.3.112",
      "dst_ip": "10.73.100.58"
    }
  ]
}
```

## Project Structure
```
├── cmd/s1ap-analyzer/    # Main application
├── pkg/s1ap/            # S1AP protocol library
├── pkg/db/              # Database integration
├── build/               # Compiled binaries
└── testdata/            # Sample files
```
