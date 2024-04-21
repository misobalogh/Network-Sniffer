# Changelog

All notable changes to this project will be documented in this file.

## [submitted]

- I am not currently aware of any features that would not work as intended according to assignment

### ⚙️ Core Functionality

- Sniffing packets that suit specified filter criteria
- Listing all available interfaces that can be sniffed on

## [unreleased]

### 🚀 Features

- CommandLineParser class for parsing arguments
- PacketCapturer for capturing packets
- Filter, OutputFormater, PacketParser

### 🐛 Bug Fixes

- Filtering by src port, dst port and port fixed
- Fixed filtering and formatting
- Byte offset lowercase
- Now also accepting ndp and mld as subset of imcp6 filter
- Filter tcp or udp and port, fixed packet length in ndp

### 🧪 Testing

- Unit tests for CLI parsing
- Integration tests in python using scapy library

<!-- generated by git-cliff -->
<!-- has been modified by author -->