#!/usr/bin/env python3
"""
Generate OpenHaystack-compatible EC P-224 key pairs for use with ESP32 tracker.

This script generates the private/public key pairs compatible with Apple's
Find My network offline finding protocol using the NIST P-224 elliptic curve.
"""

import argparse
import base64
import hashlib
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography library not found.")
    print("Install it with: pip install cryptography")
    sys.exit(1)


def generate_key_pair():
    """
    Generate an EC P-224 private/public key pair.
    
    Returns:
        tuple: (private_key_object, public_key_bytes)
    """
    # Generate private key using SECP224R1 (P-224) curve
    private_key = ec.generate_private_key(ec.SECP224R1(), default_backend())
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize public key to uncompressed format (0x04 || X || Y)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Remove the 0x04 prefix and return only the 56 bytes (28 bytes X + 28 bytes Y)
    # But OpenHaystack only uses the first 28 bytes (X coordinate)
    public_key_data = public_key_bytes[1:29]  # First 28 bytes after 0x04 prefix
    
    return private_key, public_key_data

def private_key_to_raw_b64(private_key):
    """
    Extract raw EC private scalar (28 bytes) and return base64 string.
    """
    # This is the integer private value (d)
    private_value = private_key.private_numbers().private_value

    # Convert to exactly 28 bytes (big-endian)
    raw_bytes = private_value.to_bytes(28, byteorder="big")

    # Sanity check
    if len(raw_bytes) != 28:
        raise ValueError("Invalid private key length (expected 28 bytes)")

    return base64.b64encode(raw_bytes).decode("utf-8")


def serialize_private_key(private_key):
    """
    Serialize private key to PEM format.
    
    Args:
        private_key: EC private key object
        
    Returns:
        str: PEM-encoded private key
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def generate_keys_file(num_keys, output_file, private_keys_file=None):
    """
    Generate multiple key pairs and save them to files.
    
    Args:
        num_keys: Number of key pairs to generate
        output_file: Path to output file for public keys (base64)
        private_keys_file: Optional path to save private keys
    """
    print(f"Generating {num_keys} EC P-224 key pairs...")
    
    public_keys_b64 = []
    private_keys_pem = []
    private_keys_raw_b64 = []
    
    for i in range(num_keys):
        private_key, public_key_bytes = generate_key_pair()
        
        # Encode public key as base64
        public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
        public_keys_b64.append(public_key_b64)
        
        # Serialize private key
        private_key_pem = serialize_private_key(private_key)
        private_keys_pem.append(private_key_pem)
        
        # Extract raw private scalar (OpenHaystack format)
        private_key_raw_b64 = private_key_to_raw_b64(private_key)
        private_keys_raw_b64.append(private_key_raw_b64)

        print(f"  Generated key pair {i+1}/{num_keys}")
    
    # Write public keys to file
    with open(output_file, 'w') as f:
        f.write("# OpenHaystack Public Keys (Base64 encoded)\n")
        f.write(f"# Generated {num_keys} keys for ESP32 rotation\n")
        f.write("# Each line is a base64-encoded 28-byte public key\n\n")
        for key in public_keys_b64:
            f.write(f"{key}\n")
    
    print(f"\n✓ Public keys saved to: {output_file}")
    
    # Write private keys if requested
    if private_keys_file:
        with open(private_keys_file, 'w') as f:
            f.write("# OpenHaystack Private Keys\n")
            f.write(f"# Generated {num_keys} keys - KEEP THIS FILE SECURE!\n")
            f.write("# Each key includes:\n")
            f.write("#  - RAW base64 private scalar (USE THIS with KeyPair.from_b64)\n")
            f.write("#  - PEM (backup / OpenSSL)\n")
            f.write("# Curve: secp224r1 | Private scalar size: 28 bytes\n")
            f.write("# DO NOT share this file with anyone\n\n")

            for i, (pem, raw_b64) in enumerate(
                zip(private_keys_pem, private_keys_raw_b64), start=1
            ):
                f.write(f"# Key {i}\n")
                f.write(f"RAW_BASE64: {raw_b64}\n")
                f.write(pem)
                f.write("\n")

    print(f"✓ Private keys saved to: {private_keys_file}")
    print(f"\n⚠️  WARNING: Keep {private_keys_file} secure!")
    print("   RAW_BASE64 is the value required for OpenHaystack decryption.")
    
    return public_keys_b64, private_keys_pem


def print_key_info(public_keys_b64):
    """Print information about generated keys."""
    print(f"\n{'='*70}")
    print(f"Generated {len(public_keys_b64)} key pairs")
    print(f"{'='*70}")
    print("\nFirst 3 public keys (base64):")
    for i, key in enumerate(public_keys_b64[:3]):
        print(f"  Key {i+1}: {key}")
    
    if len(public_keys_b64) > 3:
        print(f"  ... and {len(public_keys_b64) - 3} more")
    
    print(f"\n{'='*70}")
    print("Next steps:")
    print(f"{'='*70}")
    print("1. Flash the keys to your ESP32:")
    print("   ./flash_esp32.sh -p /dev/ttyUSB0 -k keys.txt")
    print("\n2. Keep your private keys safe for decrypting location data")
    print("\n3. The ESP32 will rotate through all keys every 15 minutes")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Generate EC P-224 key pairs for OpenHaystack ESP32 tracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 10 keys
  %(prog)s -n 10
  
  # Generate 100 keys with custom output files
  %(prog)s -n 100 -o my_keys.txt -p my_private_keys.pem
  
  # Generate 50 keys, public only (no private key file)
  %(prog)s -n 50 --no-private
        """
    )
    
    parser.add_argument(
        '-n', '--num-keys',
        type=int,
        default=10,
        help='Number of key pairs to generate (default: 10, max: 50000)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='keys.txt',
        help='Output file for public keys (default: keys.txt)'
    )
    
    parser.add_argument(
        '-p', '--private-keys',
        type=str,
        default='private_keys.pem',
        help='Output file for private keys (default: private_keys.pem)'
    )
    
    parser.add_argument(
        '--no-private',
        action='store_true',
        help='Do not save private keys to file'
    )
    
    args = parser.parse_args()
    
    # Validate number of keys
    if args.num_keys < 1:
        print("Error: Number of keys must be at least 1")
        sys.exit(1)
    
    if args.num_keys > 50000:
        print("Error: Maximum number of keys is 50000")
        sys.exit(1)
    
    # Check if output files already exist
    if Path(args.output).exists():
        response = input(f"Warning: {args.output} already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    
    if not args.no_private and Path(args.private_keys).exists():
        response = input(f"Warning: {args.private_keys} already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
    
    # Generate keys
    private_keys_file = None if args.no_private else args.private_keys
    public_keys_b64, _ = generate_keys_file(
        args.num_keys,
        args.output,
        private_keys_file
    )
    
    # Print summary
    print_key_info(public_keys_b64)


if __name__ == '__main__':
    main()