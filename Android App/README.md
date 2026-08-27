# AirCatch Android Companion App

An Android app that runs the AirCatch tracker-detection logic on-device. It
ingests BLE advertisements from an **attached USB serial sniffer** (e.g. the
EFR32MG24 + ESP32 USB-CDC bridge in this repo, or another Espressif/CP210x/FTDI/
CH34x serial receiver), decodes them, runs a port of the AirCatch detection
algorithm, and raises an alarm when a persistent rotating-identity tracker is
detected. Live GPS is attached to detections for context.

## Features

- **USB-host serial ingest** — connects to the sniffer over USB CDC and streams
  raw sniffer bytes into a decoder (`SnifferService`, `BleDecoder`).
- **On-device detection** — `AirCatch.kt` is a Kotlin port of the core engine
  (`WINDOW_S=120`, `DUR_MIN=1700`, `DENSITY_MIN=1.15`, core-density clustering,
  the `4C001219FC/FD/FE/FF` adversary payload tags).
- **Foreground service** with a persistent notification and a separate adversary-
  alarm channel.
- **UI tabs** — packet list, live stats, charts, and a debug view.
- **Location tagging** via Google Play Services Fused Location.

## Requirements

- **Android Studio** (Ladybug or newer recommended).
- **Android Gradle Plugin 8.13.2**, **Kotlin 2.0.21**, **JDK 17**.
- **compileSdk / targetSdk 34**, **minSdk 21**. The USB-host sniffer flow and the
  `BLUETOOTH_SCAN`/foreground-service-connected-device permissions target
  Android 12+ (API 31+); on older devices the app falls back to the legacy
  Bluetooth permissions.
- A device with **USB host (OTG)** support to attach the serial sniffer.

## Build & install

```bash
cd "Android App"
./gradlew assembleDebug
# install to a connected device/emulator:
./gradlew installDebug
```

Or open the `Android App/` folder in Android Studio and Run.

## Permissions used

Declared in `app/src/main/AndroidManifest.xml`:

- `BLUETOOTH`, `BLUETOOTH_ADMIN` (≤ API 30), `BLUETOOTH_SCAN` (neverForLocation)
- `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` (for detection context)
- `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE`,
  `FOREGROUND_SERVICE_LOCATION`, `WAKE_LOCK`
- `android.hardware.usb.host` feature + USB device filter
  (`res/xml/usb_device_filter.xml`) covering Espressif (VID `0x303A`), CP210x,
  FTDI, and CH34x serial chips.

## Supported USB serial devices

See `app/src/main/res/xml/usb_device_filter.xml`. By default the ESP32 USB-CDC
bridge from `ESP_I2C_Slave/` (Espressif VID) is recognized; add your adapter's
VID/PID there if it is not listed.

## Notes / limitations

- The app is a **companion** to the offline pipeline; it does not replace
  `Aircatch.py` for reproducing the paper's results.
- The package id is still the Android Studio default
  (`com.example.myapplication`); rename before any public release.
- Requires a compatible external sniffer — it does not detect trackers from the
  phone's own Bluetooth radio alone.
