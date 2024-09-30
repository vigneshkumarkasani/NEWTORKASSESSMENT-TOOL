# Network Compromise Assessment Tool

## Overview

The **Network Compromise Assessment Tool** is a Python-based application designed to capture and analyze network packets for suspicious activity. It aims to detect potential threats such as SYN flood attacks, Slowloris attacks, and sensitive information leakage within HTTP packets.

## Features

- **Packet Capture**: Sniff network packets in real-time using Scapy.
- **Suspicious Activity Detection**: Identify potential SYN flood and Slowloris attacks.
- **Keyword Detection**: Scan HTTP packets for sensitive keywords (e.g., passwords, tokens).
- **Logging**: Save suspicious findings to a log file for further analysis.
- **Configurable Packet Capture**: Specify the number of packets to capture via command-line arguments.

## Requirements

- Python 3.x
- Required Python packages:
  - `pyshark`
  - `scapy`
  - `colorama`

## Installation

1. Clone the repository:
   ```bash
   git clone 
   cd 


   


