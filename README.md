# AirCatch: Effectively Tracing Advanced Tag-Based Trackers

AirCatch is a comprehensive system for detecting and tracking Bluetooth Low Energy (BLE) based tag trackers (Apple AirTags, Tile, Samsung SmartTags, Google Find My, etc.) through CFO (Carrier Frequency Offset) analysis and machine learning. It enables forensic detection of malicious trackers through ecosystem-aware clustering and persistent attacker identification.

## Project Overview

This project implements an end-to-end pipeline for:
- **BLE Signal Capture**: Hardware interfaces for capturing raw IQ data from SDRs and dedicated BLE receivers (Ubertooth, USRP, EFR32)
- **Feature Extraction**: Computing CFO and other radio fingerprints from captured packets
- **Adversary Detection**: Machine learning models to identify malicious tracker behavior using density-based clustering
- **Visualization & Analysis**: Tools for analyzing tracker behavior, CFO patterns, and generating forensic reports

## Directory Structure

### Core Components

- **`Aircatch.py`** - Main detection engine implementing CFO-based adversary detection with:
  - Core density computation for robust outlier handling
  - MAC churn metrics for device mobility detection
  - Multi-ecosystem awareness (Apple, Google, Samsung, Tile)
  - Persistent attacker identification

- **`Android App/`** - Mobile companion application for on-device tracker detection

- **`BLESDR/`** - BLE software-defined radio tools for packet capture and decoding

- **`BlePhasyr_Decoder/`** - Low-level BLE packet decoder for phase and frequency analysis

- **`EFR32MG24/`** - Firmware for Silicon Labs EFR32MG24 MCU-based BLE sniffer

- **`ESP_I2C_Slave/`** - Embedded interface for I2C-based sensor integration

- **`Modified_Openhaystack_ESP32/`** - Modified OpenHaystack firmware for ESP32 devices

- **`Modified_Ubertooth/`** - Modified Ubertooth firmware enhancements for improved CFO measurement

## Key Features

### 1. CFO-Based Detection
- Extracts Carrier Frequency Offset from BLE advertisement packets
- Multiple CFO estimation methods (quick, equality-based, jump-based)
- Tracks frequency drift patterns over time for device fingerprinting

### 2. Adversary Detection Engine
- **Density-based clustering**: Identifies suspicious device clusters using core density metrics
- **MAC churn analysis**: Detects rapid MAC address changes typical of malicious trackers
- **Duration coverage**: Measures temporal persistence of suspicious activity
- **Ecosystem awareness**: Distinguishes between legitimate and adversarial behavior across tracker types

### 3. Machine Learning Pipeline
- Hierarchical agglomerative clustering
- PCA-based dimensionality reduction
- Silhouette analysis for cluster validation
- Multi-modal feature fusion (CFO, temporal, spatial)

### 4. Hardware Support
- **Ubertooth One**: Open-source BLE sniffer
- **USRP**: Software-defined radio platform
- **EFR32MG24**: Energy-efficient BLE receiver
- **ESP32**: Edge computing for distributed detection

## Installation

### Prerequisites
```bash
# Python 3.8+
pip install numpy pandas scikit-learn matplotlib scipy

# For SDR support
pip install uhd  # USRP drivers
pip install libusb1  # For Ubertooth
```

### Clone and Setup
```bash
git clone <repository_url>
cd AirCatch
python Aircatch.py --help
```

## Usage

### Basic Detection
```bash
python Aircatch.py \
    --input captured_packets.csv \
    --timestamp-col pcap_ts \
    --mac-col adv_addr \
    --cfo-cols cfo_quick_hz,cfo_equal_00_hz,cfo_equal_11_hz,cfo_jump_10_hz,cfo_jump_01_hz \
    --tag-col tag_type \
    --persist-minutes 30 \
    --drift-window-min 10 \
    --outdir results/
```

### Configuration Options

Key tunable parameters in `Aircatch.py`:

- **`WINDOW_S`**: Time window size in seconds (default: 120s)
- **`K_RANGE`**: Range of cluster numbers to test (default: 3-20)
- **`MIN_DURATION_S`**: Minimum activity duration for detection (default: 1700s)
- **`KEY_SIM_THR`**: Ecosystem similarity threshold (default: 0.99)
- **`TYPE_SEP_WEIGHT`**: Weight for ecosystem type separation (default: 1.0)

## Data Format

Input CSV should contain columns:
- `pcap_ts` - Packet timestamp
- `adv_addr` - BLE MAC address (Anonymized)
- `cfo_quick_hz` - Carrier frequency offset estimates
- `cfo_equal_00_hz`
- `cfo_equal_11_hz`
- `cfo_jump_10_hz`
- `cfo_jump_01_hz`
- `tag_type` - Device type (AirTag, Tile, etc.)

## Performance Metrics

AirCatch provides detection metrics including:
- **Precision/Recall**: For malicious tracker identification
- **Silhouette Score**: Cluster quality validation
- **MAC Churn Score**: Device behavior anomaly indicator
- **Core Density**: Robustness to outliers

## Research Output

This project supports research in:
- Privacy-preserving tracker detection
- Forensic analysis of location tracking attacks
- Cross-ecosystem security analysis
- Radio fingerprinting and device identification

## References

Related datasets and tools in this workspace:
- `../BLESDR/` - Signal processing and feature extraction
- `../UbertoothCFO/` - Ubertooth-specific CFO measurement tools
- `../bletracking/` - BLE tracking analysis utilities
- `../AirGuard/` - Android-based detection companion
