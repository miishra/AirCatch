"""Build a CSV of MAC addresses and payloads from OpenHaystack keys.

Supports two input formats:
1) Binary key partition dump: little-endian uint32 count + 28-byte entries
2) Text list of base64-encoded 28-byte keys (e.g., keys_fc.txt)

The packing mirrors main/openhaystack_main.c:
- MAC: key[0] with the two MSBs set (static random), then key[1..5]
- Payload: Apple Offline Finding frame with key[6..27] and key[0]>>6 in
  the "first 2 bits" byte (payload[29]).

Usage:
	python3 get_payloads_from_keys.py keys_fc.txt out.csv --state fd --hint fd
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import struct
from pathlib import Path
from typing import Iterable, List, Tuple


KEY_SIZE = 28


def derive_mac_and_payload(key: bytes, state_byte: int, hint_byte: int) -> Tuple[str, str]:
	"""Return (mac_str, payload_hex) for a single 28-byte key."""

	if len(key) != KEY_SIZE:
		raise ValueError(f"Expected {KEY_SIZE} key bytes, got {len(key)}")

	mac_bytes = bytearray(6)
	mac_bytes[0] = key[0] | 0xC0
	mac_bytes[1:6] = key[1:6]
	mac_str = ":".join(f"{b:02X}" for b in mac_bytes)

	payload = bytearray([
		0x1E,
		0xFF,
		0x4C, 0x00,
		0x12, 0x19,
		state_byte,
		*([0x00] * 22),
		0x00,
		hint_byte,
	])

	payload[7:29] = key[6:28]
	payload[29] = key[0] >> 6

	return mac_str, payload.hex().upper()


def read_keys_binary(raw: bytes) -> List[bytes]:
	if len(raw) < 4:
		raise ValueError("Key file too small to contain count")

	(num_keys,) = struct.unpack_from("<I", raw, 0)
	expected = 4 + num_keys * KEY_SIZE

	if len(raw) < expected:
		raise ValueError(f"Key file truncated: have {len(raw)} bytes, expected {expected}")

	keys: List[bytes] = []
	for i in range(num_keys):
		offset = 4 + i * KEY_SIZE
		keys.append(raw[offset : offset + KEY_SIZE])
	return keys


def read_keys_base64(text: str) -> List[bytes]:
	keys: List[bytes] = []
	for line_num, line in enumerate(text.splitlines(), start=1):
		stripped = line.strip()
		if not stripped or stripped.startswith("#"):
			continue
		try:
			key = base64.b64decode(stripped, validate=True)
		except binascii.Error as exc:
			raise ValueError(f"Line {line_num}: invalid base64") from exc
		if len(key) != KEY_SIZE:
			raise ValueError(f"Line {line_num}: expected {KEY_SIZE} bytes, got {len(key)}")
		keys.append(key)
	return keys


def read_keys(path: Path) -> List[bytes]:
	raw = path.read_bytes()

	try:
		text = raw.decode("utf-8")
	except UnicodeDecodeError:
		return read_keys_binary(raw)

	keys_from_text = read_keys_base64(text)
	if keys_from_text:
		return keys_from_text

	return read_keys_binary(raw)


def write_csv(keys: Iterable[bytes], csv_path: Path, state_byte: int, hint_byte: int) -> None:
	csv_path.parent.mkdir(parents=True, exist_ok=True)

	with csv_path.open("w", newline="") as f:
		writer = csv.writer(f)
		writer.writerow(["index", "mac", "payload_hex"])
		for idx, key in enumerate(keys, start=1):
			mac, payload = derive_mac_and_payload(key, state_byte, hint_byte)
			writer.writerow([idx, mac, payload])


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("key_file", type=Path, help="Key file: binary partition or base64 list")
	parser.add_argument("csv_out", type=Path, help="Output CSV path")
	parser.add_argument("--state", default="fd", help="State byte (hex, e.g. fd, fe, fc, ff)")
	parser.add_argument("--hint", default="fd", help="Hint byte (hex, e.g. fd, fe, fc, ff)")
	return parser.parse_args()


def parse_hex_byte(value: str) -> int:
	try:
		b = int(value, 16)
	except ValueError as exc:
		raise argparse.ArgumentTypeError(f"Invalid hex byte: {value}") from exc

	if not 0 <= b <= 0xFF:
		raise argparse.ArgumentTypeError(f"Hex byte out of range: {value}")
	return b


def main() -> None:
	args = parse_args()
	state_byte = parse_hex_byte(args.state)
	hint_byte = parse_hex_byte(args.hint)

	keys = read_keys(args.key_file)
	write_csv(keys, args.csv_out, state_byte, hint_byte)


if __name__ == "__main__":
	main()
