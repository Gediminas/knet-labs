#!/usr/bin/env python3
"""Skeleton BTF parser

usage: parse-btf.py [NAME|PATH] [N]
    NAME  /sys/kernel/btf/NAME (default: vmlinux)
    N     First N records (default: 15)

-------------------------------------------------------------------------------
file:    /sys/kernel/btf/wireguard (17776 bytes)
header:  9f eb 01 00 18 00 00 00 00 00 00 00 30 25 00 00 30 25 00 00 28 20 00 00
         magic=0xeb9f
         version=1
         flags=0
         hdr_len=24
         type section:   9520 bytes at 24+0
         string section: 8232 bytes at 24+9520
[165188] CONST      '(anon)'                         vlen=0 kflag=0 size_or_type=109774
...
[165195] ENUM       'noise_lengths'                  vlen=5 kflag=0 size_or_type=4
-------------------------------------------------------------------------------

Each type record is 12 bytes — `name_off`, `info` (vlen | kind | kind_flag),
`size_or_type` — followed by a kind-specific payload
"""

import struct
import sys
from collections import Counter
from pathlib import Path

SYSFS = Path("/sys/kernel/btf")
KIND = (
    "void INT PTR ARRAY STRUCT UNION ENUM FWD TYPEDEF VOLATILE CONST "
    "RESTRICT FUNC FUNC_PROTO VAR DATASEC FLOAT DECL_TAG TYPE_TAG ENUM64"
).split()

# Payload after each 12-byte record header: fixed bytes and/or per-vlen bytes.
FIXED = {1: 4, 3: 12, 14: 4, 17: 4}  # INT, ARRAY, VAR, DECL_TAG
PER_VLEN = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}  # STRUCT/UNION/ENUM/FUNC_PROTO/DATASEC/ENUM64


def parse(raw):
    """Decode the header, walk the record stream, slice out the string table."""
    if len(raw) < 24:
        sys.exit(f"error: {len(raw)} bytes is too short for a 24-byte BTF header")

    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        "<HBBIIIII", raw
    )

    if magic != 0xEB9F:
        sys.exit(f"error: bad magic {magic:#06x}, want 0xeb9f")

    # section offsets are relative to the END of the header
    recs, pos, end = [], hdr_len + type_off, hdr_len + type_off + type_len
    while pos < end:
        name_off, info, size_or_type = struct.unpack_from("<III", raw, pos)
        # info packs: vlen (bits 0-15), kind (24-28), kind_flag (31)
        kind, vlen, kflag = info >> 24 & 0x1F, info & 0xFFFF, info >> 31
        if not 0 < kind < len(KIND):
            sys.exit(f"error: bad kind {kind} at record {len(recs) + 1} — walk desynced?")
        pos += 12 + FIXED.get(kind, 0) + PER_VLEN.get(kind, 0) * vlen
        recs.append((name_off, kind, vlen, kflag, size_or_type))

    strs = raw[hdr_len + str_off : hdr_len + str_off + str_len]

    return (version, flags, hdr_len, type_off, type_len, str_off, str_len), recs, strs


def name(off, strs, base_strs):
    """NUL-terminated string at `off`. Split BTF: offsets below the base
    table's size point into vmlinux, the rest into our own section."""
    if off == 0:
        return "(anon)"

    if base_strs is not None and off >= len(base_strs):
        off -= len(base_strs)
    elif base_strs is not None:
        strs = base_strs
    return strs[off : strs.index(0, off)].decode(errors="replace")


def main():
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print(__doc__.strip())
        return

    target = args[0] if args else "vmlinux"
    show = int(args[1]) if len(args) > 1 else 15
    path = Path(target) if "/" in target else SYSFS / target
    raw = path.read_bytes()

    (version, flags, hdr_len, type_off, type_len, str_off, str_len), recs, strs = parse(raw)
    print(f"file:    {path} ({len(raw)} bytes)")
    print(f"header:  {raw[:24].hex(' ')}")
    print(f"         magic=0xeb9f version={version} flags={flags} hdr_len={hdr_len}")
    print(f"         type section: {type_len} bytes at {hdr_len}+{type_off}")
    print(f"         string section: {str_len} bytes at {hdr_len}+{str_off}")

    # Split BTF? Then some names point past our own string table, into vmlinux's.
    base_strs = None
    start_id = 1
    if max((r[0] for r in recs), default=0) >= len(strs):
        _, base_recs, base_strs = parse((SYSFS / "vmlinux").read_bytes())
        start_id = len(base_recs) + 1
        print(f"split:   names exceed own strings → base vmlinux ({len(base_recs)} types); IDs start at {start_id}")

    hist = Counter(KIND[r[1]] for r in recs)
    print(f"types:   {len(recs)} records — " + ", ".join(f"{n} {k}" for k, n in hist.most_common()))

    print(f"\nfirst {min(show, len(recs))} records (payloads skipped, not decoded):")
    for i, (name_off, kind, vlen, kflag, sot) in enumerate(recs[:show]):
        label = f"'{name(name_off, strs, base_strs)}'"
        print(f"[{start_id + i}] {KIND[kind]:<10} {label:<32} vlen={vlen} kflag={kflag} size_or_type={sot}")


if __name__ == "__main__":
    main()
