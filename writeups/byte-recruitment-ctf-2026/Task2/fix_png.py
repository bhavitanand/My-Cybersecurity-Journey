"""
fix_png.py
Repairs the corrupted BYTE Task 02 PNG.

What it does, step by step:
  1. Finds and removes the fake 12-byte IEND chunk hidden mid-stream
  2. Fixes the IHDR chunk's checksum (CRC), which was also invalid
  3. Discovers the real image height was lied about in the header, and fixes it
  4. Saves the fully repaired PNG

Usage:
    python fix_png.py challenge.png
"""

import sys
import struct
import zlib

def main():
    in_path = sys.argv[1] if len(sys.argv) > 1 else "challenge.png"
    print(f"[*] Reading {in_path}")
    data = bytearray(open(in_path, "rb").read())
    print(f"[*] File size: {len(data)} bytes")

    # --- Step 1: find and remove the fake IEND chunk ---
    first_iend = data.find(b"IEND")
    last_iend = data.rfind(b"IEND")
    if first_iend == last_iend:
        print("[!] Only found one IEND marker -- is this the original unedited file?")
        sys.exit(1)

    print(f"[*] Found fake IEND at offset 0x{first_iend:X} ({first_iend})")
    print(f"[*] Found real  IEND at offset 0x{last_iend:X} ({last_iend})")

    # the fake chunk = 4 bytes (length, which is 00 00 00 00) + "IEND" (4 bytes) + 4 bytes CRC
    chunk_start = first_iend - 4   # start of the length field
    chunk_end = first_iend + 8     # end of the CRC field
    removed = bytes(data[chunk_start:chunk_end])
    print(f"[*] Removing 12 injected bytes: {removed.hex()}")
    data = data[:chunk_start] + data[chunk_end:]
    print(f"[*] New file size: {len(data)} bytes")

    # --- Step 2: fix the IHDR chunk's CRC ---
    # IHDR always starts right after the 8-byte PNG signature + 4-byte length field
    ihdr_type_pos = 12          # offset of the 4-byte "IHDR" text
    ihdr_data_pos = 16          # offset where IHDR's 13 bytes of data begin
    ihdr_data_len = 13
    ihdr_data = bytes(data[ihdr_data_pos:ihdr_data_pos + ihdr_data_len])
    correct_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    crc_pos = ihdr_data_pos + ihdr_data_len
    old_crc = struct.unpack(">I", data[crc_pos:crc_pos + 4])[0]
    print(f"[*] IHDR CRC: stored=0x{old_crc:08X} correct=0x{correct_crc:08X}")
    data[crc_pos:crc_pos + 4] = struct.pack(">I", correct_crc)
    print("[*] IHDR CRC patched")

    # --- Step 3: figure out the real image height ---
    width = struct.unpack(">I", data[16:20])[0]
    declared_height = struct.unpack(">I", data[20:24])[0]
    print(f"[*] Declared dimensions: {width} x {declared_height}")

    # pull out all IDAT chunk data and decompress it
    i = 8
    idat = b""
    while i < len(data):
        length = struct.unpack(">I", data[i:i+4])[0]
        ctype = data[i+4:i+8]
        chunk_data = data[i+8:i+8+length]
        if ctype == b"IDAT":
            idat += chunk_data
        i += 8 + length + 4
        if ctype == b"IEND":
            break

    raw = zlib.decompress(idat)
    bytes_per_row = width * 3 + 1   # 3 bytes/pixel (RGB) + 1 filter-type byte per row
    real_height = len(raw) // bytes_per_row
    print(f"[*] Decompressed pixel data: {len(raw)} bytes -> real height = {real_height}")

    if real_height != declared_height:
        print(f"[!] Header lied! Declared {declared_height}, really {real_height}. Patching...")
        data[20:24] = struct.pack(">I", real_height)
        # recompute IHDR CRC again since we just changed its data
        ihdr_data = bytes(data[ihdr_data_pos:ihdr_data_pos + ihdr_data_len])
        correct_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
        data[crc_pos:crc_pos + 4] = struct.pack(">I", correct_crc)
        print("[*] Height + IHDR CRC patched")
    else:
        print("[*] Height matches decompressed data, no patch needed")

    # --- Step 4: save ---
    out_path = "fixed_final.png"
    open(out_path, "wb").write(data)
    print(f"[+] Done. Repaired image saved as {out_path}")
    print(f"[+] Open it and look near the bottom {max(0, real_height - declared_height)}px for the flag.")

if __name__ == "__main__":
    main()
