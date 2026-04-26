#!/usr/bin/env python3
"""
Protocol v2 connection tool for Climaton/Syncleo devices.

Reads full device state and supports commands over the encrypted v2 UDP protocol.

Requires: pip install cryptography
Usage:
    python3 connect_v2.py               # read state from token.json
    python3 connect_v2.py --set-temp 60
    python3 connect_v2.py --set-mode off|low|mid|turbo
    python3 connect_v2.py --set-keep-warm on|off
    python3 connect_v2.py --disable-heating   # set mode to off
    python3 connect_v2.py --enable-heating    # restore previous mode (low)
"""

import hashlib
import struct
import socket
import time
import datetime
import json
import sys
import argparse
import os

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("ERROR: pip install cryptography")
    sys.exit(1)

# ---------- Crypto helpers ----------

def _rotate(b: bytes, n: int) -> bytes:
    n = n % len(b)
    return b[n:] + b[:n]

def _aes_e(pt: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    return c.encryptor().update(pt) + c.encryptor().finalize()

def _aes_d(ct: bytes, key: bytes, iv: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    return c.decryptor().update(ct) + c.decryptor().finalize()

def derive_keys(device_pub_hex: str):
    """
    ECDH key exchange with Syncleo v2 device.
    
    Key insight from APK decompilation (EllipticCurveCoder.java):
    - Phone pub key is REVERSED before sending (whispersystems LE -> wire format)
    - Device pub from mDNS must be REVERSED before ECDH (same convention)
    - Shared secret is REVERSED before SHA-256 (converting LE -> consistent format)
    - SHA-256(reversed_shared)[0:16]  = encryptionInKey  (decrypt received)
    - SHA-256(reversed_shared)[16:32] = encryptionOutKey (encrypt sent)
    """
    device_pub_bytes = bytes.fromhex(device_pub_hex)
    device_pub_rev = device_pub_bytes[::-1]  # reverse before ECDH

    priv = X25519PrivateKey.generate()
    pub_wire = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_send = pub_wire[::-1]  # reverse phone pub before sending

    shared = priv.exchange(X25519PublicKey.from_public_bytes(device_pub_rev))
    shared_rev = shared[::-1]  # reverse shared secret before SHA-256
    km = hashlib.sha256(shared_rev).digest()

    enc_in  = km[:16]   # key for decrypting received frames
    enc_out = km[16:]   # key for encrypting sent frames
    return pub_send, enc_in, enc_out

# ---------- Frame helpers ----------

def build_frame(seq: int, ftype: int, payload: bytes) -> bytes:
    return struct.pack('<BBH', seq & 0xFF, ftype, len(payload)) + payload

def encrypt_frame(payload: bytes, seq: int, enc_out: bytes, enc_in: bytes) -> bytes:
    """Encrypt frame for SENDING (phone -> device). Send formula from UdpConnection.java."""
    ko = seq & 0x0F
    io = (seq >> 4) & 0x0F
    key = _rotate(enc_out, ko)
    iv  = _rotate(enc_in, io)
    pt = bytes([seq]) + payload
    pad = 16 - (len(pt) % 16)
    pt += bytes([pad] * pad)
    return _aes_e(pt, key, iv)

def decrypt_frame(ct: bytes, seq: int, enc_in: bytes, enc_out: bytes):
    """Decrypt frame RECEIVED (device -> phone). Receive formula from UdpConnection.java."""
    if not ct or len(ct) % 16 != 0:
        return None
    ko = seq & 0x0F
    io = (seq >> 4) & 0x0F
    key = _rotate(enc_in, ko)
    iv  = _rotate(enc_out, io)
    pt = _aes_d(ct, key, iv)
    pad = pt[-1]
    if 1 <= pad <= 16:
        pt = pt[:-pad]
    return pt[1:] if pt and pt[0] == seq else None

def send_ack(sock, seq: int, enc_out: bytes, enc_in: bytes, peer):
    """Send an encrypted ACK frame (protocol v2 ACKs are also encrypted)."""
    enc = encrypt_frame(bytes([]), seq, enc_out, enc_in)
    sock.sendto(build_frame(seq, 0, enc), peer)

# ---------- Temperature helpers ----------

def decode_temp(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    return (-1 if data[1] & 0x80 else 1) * (data[0] + (data[1] & 0x7F) / 100.0)

def encode_temp(temp: float) -> bytes:
    temp = max(30.0, min(75.0, temp))
    integer = int(abs(temp))
    frac = int((abs(temp) - integer) * 100)
    if temp < 0:
        frac |= 0x80
    return bytes([integer, frac])

# ---------- Connection ----------

MODES = {'off': 0, 'low': 1, 'mid': 2, 'turbo': 3}
MODE_NAMES = {0: 'Off', 1: 'Low', 2: 'Mid', 3: 'Turbo', 4: 'Waiting'}

CMD_NAMES = {
    0x00: 'Handshake', 0x01: 'Mode', 0x02: 'TargetTemp', 0x07: 'Error',
    0x10: 'KeepWarm', 0x14: 'CurrentTemp', 0x1A: 'TotalTime', 0x1F: 'Tank',
    0x28: 'SmartMode', 0x29: 'BSS', 0x31: 'Turbo', 0x33: 'Amperage',
    0x34: 'Power', 0x35: 'Voltage', 0x40: 'Schedule', 0x80: 'TimeSync',
    0x8D: 'Diagnostics', 0xFF: 'Ping',
}


class ClimatonV2:
    def __init__(self, host: str, port: int, token: bytes, device_pub_hex: str):
        self.host = host
        self.port = port
        self.token = token
        self.device_pub_hex = device_pub_hex
        self.sock = None
        self.enc_in = None
        self.enc_out = None
        self.seq = 1
        self.state = {}

    def connect(self, timeout: float = 10.0) -> bool:
        """Establish v2 encrypted connection and authenticate."""
        pub_send, enc_in, enc_out = derive_keys(self.device_pub_hex)
        self.enc_in = enc_in
        self.enc_out = enc_out

        # Encrypt token for handshake (AES/CBC/NoPadding, key=encOut, iv=encIn)
        enc_tok = _aes_e(self.token, enc_out, enc_in)
        hs_payload = bytes([0x00]) + pub_send + enc_tok

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        self.sock = sock

        sock.sendto(build_frame(0, 1, hs_payload), (self.host, self.port))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, _ = sock.recvfrom(4096)
                seq, ftype, length = struct.unpack('<BBH', data[:4])
                payload = data[4:4 + length]

                if ftype == 1 and length >= 16:  # FRAME_CMD with encrypted data
                    dec = _aes_d(payload, enc_in, enc_out)
                    pad = dec[-1]
                    if 1 <= pad <= 16:
                        dec = dec[:-pad]
                    if dec and dec[0] == 0 and dec[1] == 0:  # seq=0, cmd=0 (handshake)
                        d = dec[2:]
                        device_token = d[5:21]
                        if device_token == bytes(16):
                            print("Device rejected token (not paired)")
                            return False
                        fw = f"{d[2]}.{d[3]}"
                        # Send encrypted ACK for handshake
                        send_ack(sock, seq, enc_out, enc_in, (self.host, self.port))
                        return True
            except socket.timeout:
                pass
        return False

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send_cmd(self, cmd: int, payload: bytes = b''):
        """Send an encrypted command frame."""
        seq = self.seq
        self.seq = (self.seq + 1) & 0xFF
        frame_payload = encrypt_frame(bytes([cmd]) + payload, seq, self.enc_out, self.enc_in)
        self.sock.sendto(build_frame(seq, 1, frame_payload), (self.host, self.port))

    def _collect(self, duration: float):
        """Receive and process frames for the given duration."""
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(4096)
                seq, ftype, length = struct.unpack('<BBH', data[:4])
                payload = data[4:4 + length]

                if ftype == 1 and length >= 16:
                    dec = decrypt_frame(payload, seq, self.enc_in, self.enc_out)
                    if dec is not None:
                        send_ack(self.sock, seq, self.enc_out, self.enc_in, (self.host, self.port))
                        self._process(dec)
                    else:
                        # Might be handshake retransmit (seq=0) - ACK it
                        send_ack(self.sock, seq, self.enc_out, self.enc_in, (self.host, self.port))
            except socket.timeout:
                pass

    def _process(self, payload: bytes):
        """Process a decrypted command frame and update state."""
        if not payload:
            return
        cmd = payload[0]
        data = payload[1:]
        name = CMD_NAMES.get(cmd, f'0x{cmd:02x}')

        if cmd == 0x01 and data:
            self.state['mode'] = data[0]
        elif cmd == 0x02 and len(data) >= 2:
            self.state['target_temp'] = decode_temp(data)
        elif cmd == 0x07 and data:
            self.state['error'] = data[0]
        elif cmd == 0x10 and data:
            self.state['keep_warm'] = bool(data[0])
        elif cmd == 0x14 and len(data) >= 2:
            self.state['current_temp'] = decode_temp(data)
        elif cmd == 0x1F and data:
            self.state['tank'] = data[0]
        elif cmd == 0x28 and data:
            self.state['smart_mode'] = bool(data[0])
        elif cmd == 0x29 and data:
            self.state['bss'] = bool(data[0])
        elif cmd == 0x31 and data:
            self.state['turbo'] = bool(data[0])
        elif cmd == 0x33 and len(data) >= 2:
            self.state['amperage_raw'] = struct.unpack('<H', data[:2])[0]
        elif cmd == 0x34 and len(data) >= 2:
            self.state['power_raw'] = struct.unpack('<H', data[:2])[0]
        elif cmd == 0x35 and len(data) >= 2:
            self.state['voltage_raw'] = struct.unpack('<H', data[:2])[0]
        elif cmd == 0x40:
            schedules = self.state.setdefault('schedules', [])
            if data:
                sched_id = data[0]
                name_bytes = data[1:].rstrip(b'\x00') if len(data) > 1 else b''
                sched_name = name_bytes.lstrip(b'\x00').decode('utf-8', errors='replace')
                schedules.append({'id': sched_id, 'name': sched_name})
        elif cmd == 0x8D and data and data[0] == 0 and len(data) >= 3:
            flags = data[1]
            self.state['wifi'] = bool(flags & 4)
            self.state['mqtt'] = bool(flags & 8)
            rssi_raw = data[2]
            self.state['rssi'] = rssi_raw - 256 if rssi_raw > 127 else rssi_raw

    def fetch_state(self):
        """Send TimeSync + Diagnostics and collect all state for 5 seconds."""
        ts = int(time.time())
        off = int(datetime.datetime.now(
            datetime.timezone.utc
        ).astimezone().utcoffset().total_seconds() / 60)

        self._send_cmd(0x80, struct.pack('<iH', ts, off & 0xFFFF))
        self._send_cmd(0x8D, b'\x00')
        self._collect(5.0)

    def set_mode(self, mode: int):
        self._send_cmd(0x01, bytes([mode & 0xFF]))
        self._collect(1.0)

    def set_temperature(self, temp: float):
        self._send_cmd(0x02, encode_temp(temp))
        self._collect(1.0)

    def set_keep_warm(self, enabled: bool):
        self._send_cmd(0x10, bytes([1 if enabled else 0]))
        self._collect(1.0)

    def set_smart_mode(self, enabled: bool):
        self._send_cmd(0x28, bytes([1 if enabled else 0]))
        self._collect(1.0)

    def set_bss(self, enabled: bool):
        self._send_cmd(0x29, bytes([1 if enabled else 0]))
        self._collect(1.0)

    def set_turbo(self, enabled: bool):
        self._send_cmd(0x31, bytes([1 if enabled else 0]))
        self._collect(1.0)

    def send_ping(self):
        self._send_cmd(0xFF)


def print_state(state: dict):
    mode_n = MODE_NAMES.get(state.get('mode', -1), f"?{state.get('mode')}")
    print(f"\n  Mode:              {mode_n} ({state.get('mode', '?')})")
    print(f"  Is heating:        {state.get('mode', 0) in (1, 2, 3)}")
    print(f"  Target temp:       {state.get('target_temp', '?')}°C")
    print(f"  Current temp:      {state.get('current_temp', '?')}°C")
    print(f"  Keep warm:         {state.get('keep_warm', '?')}")
    print(f"  Smart mode:        {state.get('smart_mode', '?')}")
    print(f"  BSS (anti-leg.):   {state.get('bss', '?')}")
    print(f"  Turbo:             {state.get('turbo', '?')}")
    print(f"  Tank level:        {state.get('tank', '?')}")
    print(f"  Error code:        {state.get('error', '?')}")
    print(f"  WiFi connected:    {state.get('wifi', '?')}")
    print(f"  MQTT connected:    {state.get('mqtt', '?')}")
    print(f"  RSSI:              {state.get('rssi', '?')} dBm")
    if 'power_raw' in state:
        print(f"  Power:             {state['power_raw']}W")
    if 'amperage_raw' in state:
        print(f"  Amperage:          {state['amperage_raw'] / 100:.2f}A")
    if 'voltage_raw' in state:
        print(f"  Voltage:           {state['voltage_raw'] / 10:.1f}V")
    schedules = state.get('schedules', [])
    if schedules:
        print(f"  Schedules:")
        for s in schedules:
            print(f"    [{s['id']}] {s['name']}")


def main():
    parser = argparse.ArgumentParser(description='Climaton v2 control tool')
    parser.add_argument('--token-file', default=None, help='Path to token.json')
    parser.add_argument('--set-temp', type=float, help='Set target temperature (30-75°C)')
    parser.add_argument('--set-mode', choices=['off', 'low', 'mid', 'turbo'], help='Set mode')
    parser.add_argument('--set-keep-warm', choices=['on', 'off'], help='Keep warm on/off')
    parser.add_argument('--set-smart-mode', choices=['on', 'off'], help='Smart mode on/off')
    parser.add_argument('--set-bss', choices=['on', 'off'], help='Anti-legionella on/off')
    parser.add_argument('--disable-heating', action='store_true', help='Turn heating off (mode=0)')
    parser.add_argument('--enable-heating', action='store_true', help='Turn heating on (mode=1 Low)')
    args = parser.parse_args()

    # Find token file
    if args.token_file:
        token_file = args.token_file
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        token_file = os.path.join(script_dir, '..', 'climaton', 'token.json')

    if not os.path.exists(token_file):
        print(f"ERROR: token.json not found at {token_file}")
        print("Run pair_device_v2_improved.py first to pair the device.")
        sys.exit(1)

    with open(token_file) as f:
        cfg = json.load(f)

    if cfg.get('protocol', 1) < 2:
        print("WARNING: token.json shows protocol < 2. This tool is for v2 devices.")

    conn = ClimatonV2(
        host=cfg['device_ip'],
        port=cfg['device_port'],
        token=bytes.fromhex(cfg['token']),
        device_pub_hex=cfg['device_pub'],
    )

    print(f"Connecting to {cfg['device_ip']}:{cfg['device_port']}...")
    if not conn.connect(timeout=10.0):
        print("FAILED to connect!")
        sys.exit(1)
    print("Connected!")

    # Apply commands
    if args.set_mode:
        m = MODES[args.set_mode]
        print(f"Setting mode to {args.set_mode} ({m})...")
        conn.set_mode(m)

    if args.disable_heating:
        print("Disabling heating (mode=0)...")
        conn.set_mode(0)

    if args.enable_heating:
        print("Enabling heating (mode=1 Low)...")
        conn.set_mode(1)

    if args.set_temp is not None:
        print(f"Setting temperature to {args.set_temp}°C...")
        conn.set_temperature(args.set_temp)

    if args.set_keep_warm:
        val = args.set_keep_warm == 'on'
        print(f"Setting keep-warm to {val}...")
        conn.set_keep_warm(val)

    if args.set_smart_mode:
        val = args.set_smart_mode == 'on'
        print(f"Setting smart mode to {val}...")
        conn.set_smart_mode(val)

    if args.set_bss:
        val = args.set_bss == 'on'
        print(f"Setting BSS (anti-legionella) to {val}...")
        conn.set_bss(val)

    # Always fetch and display state
    print("\nFetching device state...")
    conn.fetch_state()

    print("\n" + "="*52)
    print("  ELECTROLUX EWH 100 SI BE EEC — DEVICE STATE")
    print("="*52)
    print_state(conn.state)
    print("="*52)

    conn.disconnect()
    print("\nDone.")


if __name__ == '__main__':
    main()
