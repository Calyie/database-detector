# Database Detector

Fast, accurate database identification and enumeration across IP ranges. Detect MySQL, PostgreSQL, MongoDB, Redis, and more with protocol verification.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

## Features

- **Multi-Database Detection**: Identifies all databases running on a single host
- **Protocol Verification**: 95% confidence through banner grabbing and protocol probing
- **Flexible Input**: Accepts structured (TXT/CSV) or unstructured text with automatic IP extraction
- **No Dependencies**: Pure Python using only standard library
- **Professional Output**: CSV format with enrichment data and confidence scores

## Supported Databases

| Database      | Default Port(s) | Protocol Verification |
|---------------|----------------|-----------------------|
| MySQL         | 3306           | ✓                     |
| PostgreSQL    | 5432           | ✓                     |
| MongoDB       | 27017          | ✓                     |
| Redis         | 6379           | ✓                     |
| MSSQL         | 1433           | ✓                     |
| Oracle        | 1521           | ✓                     |
| Cassandra     | 9042, 7000     | ✓                     |
| Elasticsearch | 9200           | ✓                     |
| CouchDB       | 5984           | ✓                     |
| InfluxDB      | 8086           | ✓                     |
| Neo4j         | 7474           | ✓                     |

## Installation
```bash
# Clone repository
git clone https://github.com/Calyie/database-detector.git
cd database-detector

# Make executable (Linux/Mac)
chmod +x db_detector.py

# Optional: Install globally
sudo cp db_detector.py /usr/local/bin/db-detector
```

**Requirements**: Python 3.7+ (no external dependencies)

## Quick Start
```bash
# Basic scan
python db_detector.py ips.txt

# Custom output file and threading
python db_detector.py ips.txt -o results.csv -t 200

# Increase timeout for slow networks
python db_detector.py ips.txt --timeout 5.0

# List all supported databases
python db_detector.py -l
```

## Usage
```
╔═══════════════════════════════════════════════════════════════╗
║                    DATABASE DETECTOR                          ║
║          Fast Database Identification & Enumeration           ║
╚═══════════════════════════════════════════════════════════════╝

usage: db_detector.py [-h] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] 
                      [-q] [-l] [-v] [input]

positional arguments:
  input                 Input file containing IPv4 addresses

optional arguments:
  -o OUTPUT             Output CSV file (default: db_detections.csv)
  -t THREADS            Number of threads (default: 100, max: 1000)
  --timeout TIMEOUT     Connection timeout in seconds (default: 2.0)
  -q, --quiet          Quiet mode - minimal output
  -l, --list           List supported database types
  -v, --version        Show version
```

## Input Formats

Database Detector automatically extracts IPs from various formats:

**Structured (one per line):**
```
192.168.1.1
192.168.1.2
10.0.0.50
```

**CSV:**
```
hostname,ip,subnet
server1,192.168.1.1,10.0.0.0/24
server2,192.168.1.2,10.0.0.0/24
```

**Unstructured text:**
```
Found these servers: 192.168.1.1, 192.168.1.2
Additional hosts: 10.0.0.50;10.0.0.51
```

All formats work - IPs are extracted via regex.

## Output Example
```csv
ip,port,db_type,confidence,verified,reason
192.168.1.100,3306,MySQL,0.95,True,Protocol verified
192.168.1.100,6379,Redis,0.95,True,Protocol verified
10.0.0.50,5432,PostgreSQL,0.60,False,Port open, protocol unverified
10.0.0.50,27017,MongoDB,0.95,True,Protocol verified
```

**Fields:**
- `ip`: Target IP address
- `port`: Database port
- `db_type`: Detected database type
- `confidence`: Detection confidence (0.0-1.0)
- `verified`: Protocol verification status
- `reason`: Detection method details

## Use Cases

- **Security Audits**: Identify exposed databases in your network
- **Asset Discovery**: Map database infrastructure across environments
- **Compliance**: Verify database inventory for regulatory requirements
- **Red Team/Pentesting**: Reconnaissance phase of security assessments
- **Cloud Inventory**: Discover databases across cloud environments

## Security & Ethics

This tool is intended for:
- Security professionals auditing systems they own or have authorization to test
- Network administrators conducting inventory of their infrastructure
- Researchers with explicit permission

**Always ensure you have proper authorization before scanning networks.**

## How It Works

1. **IP Extraction**: Regex-based extraction and validation of IPv4 addresses
2. **Port Scanning**: Concurrent connection attempts to known database ports
3. **Banner Grabbing**: Capture initial server responses
4. **Protocol Verification**: Send database-specific handshakes to confirm type
5. **Confidence Scoring**: Assign confidence based on verification level
6. **Results Aggregation**: Output all findings to CSV

## Contributing

Contributions are welcome! Here's how you can help:

- **Add database support**: Implement detection for additional databases
- **Improve accuracy**: Enhance protocol verification methods
- **Performance optimization**: Speed improvements or memory efficiency
- **Bug fixes**: Report and fix issues
- **Documentation**: Improve docs or add examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Roadmap

- [ ] IPv6 support
- [ ] JSON output format
- [ ] Integration with security scanners (Nmap, Masscan)
- [ ] Version detection for databases
- [ ] Credential testing (with authorization)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

Built for security professionals and network administrators who need fast, reliable database discovery.

## Author

[Your Name](https://github.com/Calyie)

---

**If you find this tool useful, please ⭐ star the repository!**
```

---
