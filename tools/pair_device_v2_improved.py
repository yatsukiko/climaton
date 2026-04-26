#!/usr/bin/env python3
"""
Protocol v2 pairing script for Climaton/Syncleo devices.

Press the WiFi/pairing button on the water heater, then run this script.
The device enters pairing mode for ~20 seconds; the script polls until it sees
a valid token in the handshake response and saves it to climaton/token.json.

Key derivation (from APK decompilation of EllipticCurveCoder.java):
  - Phone pub key is byte-reversed before sending (whispersystems LE format)
  - Device mDNS pub key is byte-reversed before ECDH (same convention)
  - Shared secret is byte-reversed before SHA-256
  - SHA-256(reversed_shared)[0:16]  = encryptionInKey
  - SHA-256(reversed_shared)[16:32] = encryptionOutKey

Usage:
    python3 pair_device_v2_improved.py <host> --device-pub <hex>

The device pub hex comes from mDNS TXT 'public=' field (avahi-browse -r -t _syncleo._udp).

Requires: pip install cryptography
"""

import socket
import struct
import time
import json
import os
import sys
import hashlib
import argparse

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("ERROR: 'cryptography' package required.  pip install cryptography")
    sys.exit(1)

parser = argparse.ArgumentParser(description="Pair with a Protocol v2 Climaton/Syncleo device")
parser.add_argument("host", help="Device IP address")
parser.add_argument("--port", type=int, default=41122, help="UDP port (default: 41122)")
parser.add_argument("--device-pub", required=True,
                    help="Device X25519 public key hex (32 bytes, from mDNS TXT 'public=' field)")
args = parser.parse_args()

DEVICE_IP = args.host
DEVICE_PORT = args.port
DEVICE_PUB_HEX = args.device_pub.strip()

if len(DEVICE_PUB_HEX) != 64:
    print(f"ERROR: --device-pub must be 64 hex chars (32 bytes), got {len(DEVICE_PUB_HEX)}")
    sys.exit(1)


def _aes_e(pt: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    return c.encryptor().update(pt) + c.encryptor().finalize()

def _aes_d(ct: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    return c.decryptor().update(ct) + c.decryptor().finalize()

def build_frame(seq: int, ftype: int, payload: bytes) -> bytes:
    return struct.pack('<BBH', seq & 0xFF, ftype, len(payload)) + payload


def attempt_pair(sock) -> tuple | None:
    """
    Send a zero-token v2 handshake and parse the device's response.

    Returns (token, protocol, fw_major, fw_minor, mode) when device is in pairing
    mode and returns a valid non-zero token, else None.
    """
    device_pub_rev = bytes.fromhex(DEVICE_PUB_HEX)[::-1]

    priv = X25519PrivateKey.generate()
    pub_send = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)[::-1]

    shared = priv.exchange(X25519PublicKey.from_public_bytes(device_pub_rev))
    km = hashlib.sha256(shared[::-1]).digest()
    enc_in  = km[:16]
    enc_out = km[16:]

    # Encrypt zero token (pairing probe): AES/CBC/NoPadding, key=encOut, iv=encIn
    enc_token = _aes_e(bytes(16), enc_out, enc_in)
    hs_payload = bytes([0x00]) + pub_send + enc_token  # 49 bytes
    sock.sendto(build_frame(0, 1, hs_payload), (DEVICE_IP, DEVICE_PORT))

    # Collect frames
    frames = []
    deadline = time.time() + 2.5
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
            seq, ftype, flen = struct.unpack('<BBH', data[:4])
            frames.append((seq, ftype, flen, data[4:4 + flen]))
            if ftype == 1:
                # Send encrypted ACK (v2 ACKs carry a 16-byte ciphertext payload)
                ko = seq & 0x0F
                io = (seq >> 4) & 0x0F
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as _modes
                def _rot(b, n): n = n % len(b); return b[n:] + b[:n]
                key = _rot(enc_out, ko); iv = _rot(enc_in, io)
                pt = bytes([seq]); pad = 16 - len(pt); pt += bytes([pad] * pad)
                enc_ack = Cipher(algorithms.AES(key), _modes.CBC(iv)).encryptor().update(pt)
                sock.sendto(build_frame(seq, 0, enc_ack), (DEVICE_IP, DEVICE_PORT))
        except socket.timeout:
            break

    # The device CMD response (32 bytes) is the AES-encrypted handshake reply.
    # Decrypt with RECEIVE formula: key=encIn (no rotation for seq=0), iv=encOut.
    cmd_f = next((f for f in frames if f[1] == 1 and f[2] >= 16), None)
    if not cmd_f:
        return None

    ct = cmd_f[3]
    try:
        dec = _aes_d(ct, enc_in, enc_out)
        pad = dec[-1]
        if 1 <= pad <= 16 and all(b == pad for b in dec[-pad:]):
            dec = dec[:-pad]
    except Exception:
        return None

    # Expect: [seq=0][cmd=0x00][proto(2)][fw_maj][fw_min][mode][token(16)]
    if len(dec) < 22 or dec[0] != 0 or dec[1] != 0:
        return None

    data = dec[2:]
    proto   = struct.unpack('<H', data[0:2])[0]
    fw_maj  = data[2]
    fw_min  = data[3]
    mode    = data[4]
    token   = data[5:21]

    if token == bytes(16):
        return None  # device rejected / not in pairing mode

    return token, proto, fw_maj, fw_min, mode


def main():
    print("=" * 60)
    print("  CLIMATON PAIRING TOOL — Protocol v2")
    print("=" * 60)
    print(f"\nTarget:     {DEVICE_IP}:{DEVICE_PORT}")
    print(f"Device pub: {DEVICE_PUB_HEX}")
    print()
    print(">>> Press the WiFi/pairing button on the water heater NOW <<<")
    print()
    print("Polling every 1.5 seconds (Ctrl+C to abort)...")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    attempt = 0
    try:
        while True:
            attempt += 1
            print(f"  [{attempt:3d}] ", end="", flush=True)

            result = attempt_pair(sock)
            if result is None:
                print("no valid token (not in pairing mode)")
            else:
                token, proto, fw_maj, fw_min, mode = result
                print(f"\n\n  *** PAIRED SUCCESSFULLY! ***")
                print(f"  Token:    {token.hex()}")
                print(f"  Protocol: {proto},  Firmware: {fw_maj}.{fw_min},  Mode: {mode}")

                token_file = os.path.join(
                    os.path.dirname(__file__), "..", "climaton", "token.json"
                )
                os.makedirs(os.path.dirname(token_file), exist_ok=True)
                with open(token_file, "w") as f:
                    json.dump({
                        "token":      token.hex(),
                        "device_ip":  DEVICE_IP,
                        "device_port": DEVICE_PORT,
                        "protocol":   proto,
                        "firmware":   f"{fw_maj}.{fw_min}",
                        "device_pub": DEVICE_PUB_HEX,
                    }, f, indent=2)
                print(f"\n  Saved to: {os.path.abspath(token_file)}")
                break

            time.sleep(1.5)

    except KeyboardInterrupt:
        print("\n\nAborted.")

    sock.close()


if __name__ == "__main__":
    main()
