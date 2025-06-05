# PyGuard: A Simple Intrusion Detection System

PyGuard is a Python-based Intrusion Detection System (IDS) designed to monitor network traffic and detect potential intrusions or suspicious activities.

## Features

- Real-time network packet capture and analysis
- Rule-based detection engine
- Detection of common attack patterns:
  - Port scanning
  - Brute force attacks
  - SQL injection attempts
  - Cross-site scripting (XSS)
  - Denial of Service (DoS) attacks
  - And more...
- Customizable detection rules
- Alert generation and management
- Logging and reporting

## Requirements

- Python 3.6 or higher
- Scapy
- Pcapy or PyPcap
- Other dependencies listed in requirements.txt

## Installation

1. Clone the repository or download the source code
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

To start PyGuard, run the `main.py` script:

```bash
python main.py
```

By default, PyGuard will attempt to auto-detect your network interface and use default settings.

### Command-line Options

```bash
usage: main.py [-h] [-i INTERFACE] [-c CONFIG] [-l {debug,info,warning,error,critical}] [-o OUTPUT] [-t TIMEOUT]
```

- `-h, --help` : Show the help message and exit
- `-i, --interface` : Specify the network interface to monitor
- `-c, --config` : Path to configuration file (default: `config/settings.py`)
- `-l, --log` : Set logging level: `debug`, `info`, `warning`, `error`, `critical` (default: `info`)
- `-o, --output` : Output file for alerts
- `-t, --timeout` : Monitoring timeout in seconds (0 for indefinite, which is the default)

Example:

```bash
python main.py -i eth0 -l debug -t 300
```

This will monitor the `eth0` interface with debug-level logging for 5 minutes.

## Configuration

PyGuard can be configured through the settings file. The default settings are defined in `config/settings.py`, but you can create a custom configuration file in JSON format.

Default configuration locations:

- `config.json` in the current directory
- `~/.pyguard/config.json` in the user's home directory
- `/etc/pyguard/config.json` for system-wide configuration

### Key Configuration Options

- `interface` : Network interface to monitor (auto-detected if not specified)
- `packet_filter` : BPF syntax filter for capturing specific packets
- `log_level` : Logging verbosity (`INFO`, `DEBUG`, `WARNING`, `ERROR`, `CRITICAL`)
- `log_file` : Path to log file
- `alert_file` : Path to alerts JSON file
- `alert_time_window` : Time window in seconds for alert rate limiting
- `port_scan_threshold` : Number of ports to trigger port scan detection
- `history_size` : Number of packets to keep in history for analysis

## Detection Rules

PyGuard uses a rule-based detection system. Default rules are defined in `config/rules.py`, but you can create custom rules in JSON format.

Default rule file locations:

- `rules.json` in the current directory
- `~/.pyguard/rules.json` in the user's home directory
- `/etc/pyguard/rules.json` for system-wide rules

### Rule Structure

Each rule is a JSON object with the following properties:

```json
{
  "id": "RULE_ID",
  "type": "tcp|udp|icmp",
  "message": "Alert message",
  "severity": "low|medium|high",
  "dst_port": 80,         // Optional, specific destination port
  "src_port": 1024,       // Optional, specific source port
  "flags": "S",          // Optional, TCP flags (for TCP type)
  "icmp_type": 8,         // Optional, ICMP type (for ICMP type)
  "pattern": "regex"     // Optional, regex pattern to match in payload
}
```

## Alerts

Alerts are generated when suspicious activity is detected. They are logged to the console, the log file, and saved to the alerts JSON file.

Alert severity levels:

- `low` : Informational, potentially suspicious
- `medium` : Suspicious activity that warrants investigation
- `high` : Likely malicious activity requiring immediate attention

## Extending PyGuard

PyGuard is designed to be modular and extensible. You can:

1. Add custom detection rules
2. Implement new alert actions (email, SIEM integration, etc.)
3. Extend the analyzer with new traffic pattern recognition
4. Add new packet processing capabilities

## Troubleshooting

### Common Issues

1. **Permission errors** : Packet capture requires administrative privileges
   - Run as administrator on Windows
   - Use `sudo` on Linux/macOS
2. **Interface not found** : Verify the interface name
   - On Windows: Use `ipconfig` to list interfaces
   - On Linux: Use `ip a` or `ifconfig` to list interfaces
3. **No packets captured** : Check firewall settings and interface status

## License

This project is licensed under the MIT License - see the LICENSE file for details.
