# AirCatch — pinned environment for artifact evaluation.
#
# Two build targets:
#
#   analysis (default) -- host-side analysis only. This is all a reviewer needs
#                         for the Functional badge; no hardware required.
#       docker build -t aircatch:main .
#       docker run --rm aircatch:main
#
#   hardware           -- adds the firmware flashing / capture toolchain
#                         (OpenOCD, esptool, dfu-util, Ubertooth host tools,
#                         arm-none-eabi). Needs USB passthrough to be useful.
#       docker build --target hardware -t aircatch:hw .
#       docker run --rm -it --device=/dev/ttyUSB0 aircatch:hw bash
#
# Matches the interpreter and package versions used for the paper's results
# (Python 3.12, see requirements.txt).

# ============================================================== analysis stage
FROM python:3.12-slim-bookworm AS analysis

# build-essential/cmake/libssl-dev are only needed to build BLESDR/iq2pcap.
# Keeping them in makes `cmake --build` in the README work inside the container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /artifact

# Dependencies first so edits to the code don't invalidate the pip layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# matplotlib has no display in a container; force the non-interactive backend
# and give it a writable config dir (the default $HOME may not be writable).
ENV MPLBACKEND=Agg \
    MPLCONFIGDIR=/tmp/mpl \
    PYTHONDONTWRITEBYTECODE=1

RUN chmod +x test.sh

# Default: run the functional test. Override to get a shell, e.g.
#   docker run --rm -it --entrypoint bash aircatch:main
CMD ["./test.sh"]

# ============================================================== hardware stage
FROM analysis AS hardware

# Flashing and capture toolchain:
#   dfu-util              -- DFU-mode recovery
#   ubertooth + libbtbb   -- Ubertooth One host tools (ubertooth-btle)
#   libusb-1.0            -- USB backend for the above
#   gcc-arm-none-eabi     -- rebuild the patched Ubertooth firmware
#   pkg-config/libbtbb-dev-- rebuild the patched Ubertooth host library
RUN apt-get update && apt-get install -y --no-install-recommends \
        dfu-util \
        ubertooth \
        libbtbb-dev \
        libusb-1.0-0 \
        libusb-1.0-0-dev \
        gcc-arm-none-eabi \
        pkg-config \
        usbutils \
        minicom \
    && rm -rf /var/lib/apt/lists/*

# esptool flashes the ESP32 (bridge firmware and the OpenHaystack adversary).
# Modified_Openhaystack_ESP32/flash_esp32.sh normally builds its own venv for
# this; with esptool already present it can be invoked directly.
RUN pip install --no-cache-dir esptool==5.1.0

# The EFR32MG24 needs OpenOCD's efm32s2 flash driver, which the 0.12.0 release
# (and therefore Debian's openocd package) does not have. flash.sh uses the
# build bundled at tools/openocd-silabs/ instead -- already present via COPY.
# See tools/openocd-silabs/README.md.
RUN test -x tools/openocd-silabs/bin/openocd \
    && tools/openocd-silabs/bin/openocd --version

CMD ["bash"]

# =============================================================== default stage
# A bare `docker build .` resolves to the LAST stage in the file, so this alias
# keeps the lean analysis image as the default and makes the hardware toolchain
# strictly opt-in via `--target hardware`.
FROM analysis AS default
