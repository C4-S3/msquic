#!/usr/bin/env python3
"""
Generate seed corpus for QUIC frame fuzzing
Based on RFC 9000 QUIC frame formats

Usage:
    python3 generate_corpus.py
    Creates corpus/ directory with seed files
"""

import struct
import os
import sys

def varint_encode(value):
    """Encode QUIC variable-length integer per RFC 9000"""
    if value < 0:
        raise ValueError("VarInt must be non-negative")
    if value > 0x3FFFFFFFFFFFFFFF:
        raise ValueError("VarInt too large")

    if value < 64:
        return bytes([value])
    elif value < 16384:
        return struct.pack('>H', value | 0x4000)
    elif value < 1073741824:
        return struct.pack('>I', value | 0x80000000)
    else:
        return struct.pack('>Q', value | 0xC000000000000000)

def generate_stream_frame(stream_id, offset, data, fin=False, explicit_length=True):
    """
    Generate STREAM frame (0x08-0x0f)

    Frame format:
    - Type (i): 0x08..0x0f
    - Stream ID (i)
    - [Offset (i)]      (if OFF bit set)
    - [Length (i)]      (if LEN bit set)
    - Stream Data (..)
    """
    # Frame type with flags: 0x08 | OFF(0x04) | LEN(0x02) | FIN(0x01)
    frame_type = 0x08
    if offset > 0:
        frame_type |= 0x04  # OFF bit
    if explicit_length:
        frame_type |= 0x02  # LEN bit
    if fin:
        frame_type |= 0x01  # FIN bit

    frame = bytes([frame_type])
    frame += varint_encode(stream_id)

    if offset > 0:
        frame += varint_encode(offset)

    if explicit_length:
        frame += varint_encode(len(data))

    frame += data
    return frame

def generate_crypto_frame(offset, data):
    """
    Generate CRYPTO frame (0x06)

    Frame format:
    - Type (i): 0x06
    - Offset (i)
    - Length (i)
    - Crypto Data (..)
    """
    frame = bytes([0x06])
    frame += varint_encode(offset)
    frame += varint_encode(len(data))
    frame += data
    return frame

def generate_ack_frame(largest_ack, ack_delay, first_range, ranges=None):
    """
    Generate ACK frame (0x02)

    Frame format:
    - Type (i): 0x02
    - Largest Acknowledged (i)
    - ACK Delay (i)
    - ACK Range Count (i)
    - First ACK Range (i)
    - [ACK Range (..) ...]
    """
    frame = bytes([0x02])
    frame += varint_encode(largest_ack)
    frame += varint_encode(ack_delay)

    if ranges is None:
        ranges = []

    frame += varint_encode(len(ranges))  # ACK Range Count
    frame += varint_encode(first_range)   # First ACK Range

    for gap, ack_range in ranges:
        frame += varint_encode(gap)
        frame += varint_encode(ack_range)

    return frame

def generate_new_token_frame(token):
    """
    Generate NEW_TOKEN frame (0x07)

    Frame format:
    - Type (i): 0x07
    - Token Length (i)
    - Token (..)
    """
    frame = bytes([0x07])
    frame += varint_encode(len(token))
    frame += token
    return frame

def generate_connection_close_frame(error_code, frame_type, reason):
    """
    Generate CONNECTION_CLOSE frame (0x1c)

    Frame format:
    - Type (i): 0x1c
    - Error Code (i)
    - Frame Type (i)
    - Reason Phrase Length (i)
    - Reason Phrase (..)
    """
    frame = bytes([0x1c])
    frame += varint_encode(error_code)
    frame += varint_encode(frame_type)
    frame += varint_encode(len(reason))
    frame += reason.encode('utf-8') if isinstance(reason, str) else reason
    return frame

def generate_corpus():
    """Generate comprehensive seed corpus for frame fuzzing"""
    os.makedirs('corpus', exist_ok=True)

    frames = []

    print("[*] Generating STREAM frame seeds...")

    # Basic STREAM frames
    frames.append(('stream_basic', b'\x00' + generate_stream_frame(0, 0, b'Hello QUIC')))
    frames.append(('stream_fin', b'\x00' + generate_stream_frame(0, 0, b'Last packet', fin=True)))
    frames.append(('stream_offset', b'\x00' + generate_stream_frame(0, 1000, b'Data at offset')))
    frames.append(('stream_large_id', b'\x00' + generate_stream_frame(0x3FFFFFFF, 0, b'Large stream ID')))

    # Edge cases for STREAM
    frames.append(('stream_empty', b'\x00' + generate_stream_frame(0, 0, b'')))
    frames.append(('stream_no_len', b'\x00' + generate_stream_frame(0, 0, b'Implicit length', explicit_length=False)))

    # Potential overflow triggers for STREAM
    frames.append(('stream_max_offset', b'\x00' + generate_stream_frame(0, 0x3FFFFFFFFFFFFFFF, b'Max offset')))

    print("[*] Generating CRYPTO frame seeds...")

    # Basic CRYPTO frames
    frames.append(('crypto_basic', b'\x01' + generate_crypto_frame(0, b'ClientHello')))
    frames.append(('crypto_offset', b'\x01' + generate_crypto_frame(512, b'Continued crypto data')))

    # Edge cases for CRYPTO
    frames.append(('crypto_empty', b'\x01' + generate_crypto_frame(0, b'')))
    frames.append(('crypto_large', b'\x01' + generate_crypto_frame(0, b'X' * 1000)))

    print("[*] Generating ACK frame seeds...")

    # Basic ACK frames
    frames.append(('ack_simple', b'\x00' + generate_ack_frame(100, 25, 10)))
    frames.append(('ack_large', b'\x00' + generate_ack_frame(1000000, 50, 100)))

    # ACK with ranges
    frames.append(('ack_ranges', b'\x00' + generate_ack_frame(1000, 25, 10, [(5, 10), (5, 20)])))

    # Edge cases for ACK
    frames.append(('ack_max_acked', b'\x00' + generate_ack_frame(0x3FFFFFFFFFFFFFFF, 0, 0)))

    print("[*] Generating NEW_TOKEN frame seeds...")

    # Basic NEW_TOKEN frames
    frames.append(('token_basic', b'\x02' + generate_new_token_frame(b'token123456789')))
    frames.append(('token_large', b'\x02' + generate_new_token_frame(b'T' * 500)))

    # Edge cases
    frames.append(('token_empty', b'\x02' + generate_new_token_frame(b'')))

    print("[*] Generating CONNECTION_CLOSE frame seeds...")

    # Basic CONNECTION_CLOSE
    frames.append(('close_basic', b'\x00' + generate_connection_close_frame(0, 0, 'Normal close')))
    frames.append(('close_error', b'\x00' + generate_connection_close_frame(0x01, 0, 'Internal error')))

    # Edge cases
    frames.append(('close_no_reason', b'\x00' + generate_connection_close_frame(0, 0, '')))
    frames.append(('close_long_reason', b'\x00' + generate_connection_close_frame(0, 0, 'R' * 1000)))

    print("[*] Generating edge case seeds...")

    # Integer boundary values for VarInt
    varint_edges = [
        0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824,
        0x3FFFFFFFFFFFFFFF  # Max VarInt
    ]

    for i, val in enumerate(varint_edges):
        try:
            frames.append((f'edge_varint_{i}', b'\x00' + generate_stream_frame(val, 0, b'Edge')))
        except:
            pass  # Skip if value too large

    # Malformed / attack seeds
    print("[*] Generating attack pattern seeds...")

    # Large length field (potential overflow trigger)
    attack_frame = b'\x01'  # Select CRYPTO
    attack_frame += bytes([0x06])  # CRYPTO frame type
    attack_frame += varint_encode(0)  # Offset = 0
    attack_frame += varint_encode(0xFFFFFFFF)  # Huge length
    attack_frame += b'A' * 100  # But only small amount of data
    frames.append(('attack_huge_length', attack_frame))

    # Maximum values everywhere
    attack_frame2 = b'\x00'  # Select STREAM
    attack_frame2 += bytes([0x0F])  # STREAM with all flags
    attack_frame2 += varint_encode(0x3FFFFFFFFFFFFFFF)  # Max stream ID
    attack_frame2 += varint_encode(0x3FFFFFFFFFFFFFFF)  # Max offset
    attack_frame2 += varint_encode(0x3FFFFFFFFFFFFFFF)  # Max length
    attack_frame2 += b'X' * 10
    frames.append(('attack_max_values', attack_frame2))

    # Write all corpus files
    print(f"[*] Writing {len(frames)} seed files to corpus/...")
    for i, (name, frame_data) in enumerate(frames):
        with open(f'corpus/{name}', 'wb') as f:
            f.write(frame_data)

    print(f"[+] Generated {len(frames)} seed files in corpus/")
    print(f"[+] Corpus ready for fuzzing!")

if __name__ == '__main__':
    generate_corpus()
