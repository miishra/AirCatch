# Bundled OpenOCD (Silicon Labs build)

A prebuilt OpenOCD used by [`../../EFR32MG24/Flashing/flash.sh`](../../EFR32MG24/Flashing/flash.sh)
to program the Seeed XIAO EFR32MG24 over SWD.

```
Open On-Chip Debugger 0.12.0+dev-01514-g21fa2de70 (2024-02-07-19:19)
```

## Why this is bundled rather than installed from a package manager

The EFR32MG24 is an **EFM32 Series 2** part, and programming it needs OpenOCD's
`efm32s2` flash driver. That driver is **not** in the OpenOCD 0.12.0 release, so
distribution packages (Debian/Ubuntu `openocd`, Homebrew, …) cannot flash this
board — they ship only the older `efm32x` driver:

| Build | `efm32s2` driver | Programs EFR32MG24 |
|---|---|---|
| OpenOCD 0.12.0 release (Debian `openocd`) | absent | no |
| This build, 0.12.0+dev-01514-g21fa2de70 | present | yes |

The vendor target configs `efm32s2.cfg` and `efm32s2_g23.cfg` (the latter sets
`FLASHBASE 0x08000000` for family group 23) also ship only with this build.

Attempting the flash with an unequipped OpenOCD erases the device and then fails
to program it, so `flash.sh` checks for the driver and refuses to start rather
than leaving the board bricked.

## Provenance

Taken verbatim from the Silicon Labs Arduino core's toolchain package:

```
~/.arduino15/packages/SiliconLabs/tools/openocd/0.12.0-arduino1-static/
```

installed by the [Silicon Labs Arduino core](https://github.com/SiliconLabs/arduino).

## License

OpenOCD is **GPL-2.0**. `bin/openocd` here is an unmodified binary of the
upstream project at commit `21fa2de70`; the corresponding source is available
from the OpenOCD project:

- <https://openocd.org/>
- <https://sourceforge.net/p/openocd/code/> (commit `21fa2de70`)

The `share/openocd/scripts/` tree is the configuration set distributed with that
build, under the same license. No modifications were made by the AirCatch
authors.

## Platform

`bin/openocd` is a **static x86-64 Linux** executable. It works on x86-64 Linux
hosts and inside the project's `hardware` container. On macOS, Windows, or ARM
hosts, install the Silicon Labs Arduino core to obtain the equivalent build for
your platform and point `flash.sh` at it:

```bash
OPENOCD=/path/to/openocd \
OPENOCD_SCRIPTS=/path/to/share/openocd/scripts \
    ../../EFR32MG24/Flashing/flash.sh firmware.hex
```
