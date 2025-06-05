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