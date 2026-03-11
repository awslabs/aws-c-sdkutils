#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.

"""Partition bytecode compiler: partitions.json -> binary with string blob."""

import json
import struct
import sys

MAGIC = 0x50415254  # "PART"


class StringBlob:
    def __init__(self):
        self._blob = bytearray()
        self._index = {}

    def add(self, s):
        if not s:
            return (0, 0)
        if s not in self._index:
            encoded = s.encode("utf-8")
            offset = len(self._blob)
            if offset > 0xFFFF or len(encoded) > 0xFFFF:
                raise ValueError(f"String blob overflow: offset={offset} len={len(encoded)}")
            self._blob.extend(encoded)
            self._index[s] = (offset, len(encoded))
        return self._index[s]

    def blob(self):
        return bytes(self._blob)


def write_ref(buf, offset, length):
    buf.extend(struct.pack("<HH", offset, length))


def is_copy_region(region_obj):
    """Region is a copy (no real override) if it has no keys or only 'description'."""
    keys = set(region_obj.keys()) - {"description"}
    return len(keys) == 0


def compile_partitions(data, strings):
    """Pre-collect all strings, then encode."""
    version = data.get("version", "")
    strings.add(version)

    partitions = data.get("partitions", [])
    for p in partitions:
        strings.add(p.get("id", ""))
        strings.add(p.get("regionRegex", ""))
        outputs = p.get("outputs", {})
        outputs_json = json.dumps(outputs, separators=(",", ":"), sort_keys=True)
        strings.add(outputs_json)
        for region_name, region_obj in p.get("regions", {}).items():
            strings.add(region_name)
            if not is_copy_region(region_obj):
                # Merge: start from outputs, apply non-description overrides
                merged = dict(outputs)
                for k, v in region_obj.items():
                    if k != "description":
                        merged[k] = v
                merged_json = json.dumps(merged, separators=(",", ":"), sort_keys=True)
                strings.add(merged_json)

    buf = bytearray()
    buf += struct.pack("<I", MAGIC)
    blob = strings.blob()
    buf += struct.pack("<I", len(blob))
    buf += blob

    # version ref
    write_ref(buf, *strings.add(version))

    # partition count
    buf += struct.pack("<H", len(partitions))

    for p in partitions:
        pid = p.get("id", "")
        regex = p.get("regionRegex", "")
        outputs = p.get("outputs", {})
        outputs_json = json.dumps(outputs, separators=(",", ":"), sort_keys=True)

        write_ref(buf, *strings.add(pid))
        write_ref(buf, *strings.add(outputs_json))
        write_ref(buf, *strings.add(regex))

        regions = p.get("regions", {})
        buf += struct.pack("<H", len(regions))

        for region_name, region_obj in regions.items():
            write_ref(buf, *strings.add(region_name))
            if is_copy_region(region_obj):
                buf += struct.pack("<B", 0)  # has_override = false
            else:
                buf += struct.pack("<B", 1)  # has_override = true
                merged = dict(outputs)
                for k, v in region_obj.items():
                    if k != "description":
                        merged[k] = v
                merged_json = json.dumps(merged, separators=(",", ":"), sort_keys=True)
                write_ref(buf, *strings.add(merged_json))

    return bytes(buf)


def verify(bin_path):
    with open(bin_path, "rb") as f:
        data = f.read()
    pos = 0

    def read(fmt):
        nonlocal pos
        size = struct.calcsize(fmt)
        val = struct.unpack_from(fmt, data, pos)
        pos += size
        return val[0] if len(val) == 1 else val

    magic = read("<I")
    if magic != MAGIC:
        print(f"ERROR: bad magic 0x{magic:08X} (expected 0x{MAGIC:08X})", file=sys.stderr)
        sys.exit(1)

    blob_size = read("<I")
    blob = data[pos:pos + blob_size]
    pos += blob_size

    def read_ref():
        nonlocal pos
        off, ln = struct.unpack_from("<HH", data, pos)
        pos += 4
        return blob[off:off + ln].decode("utf-8") if ln else ""

    version = read_ref()
    partition_count = read("<H")

    print(f"Magic:           0x{magic:08X}")
    print(f"Blob size:       {blob_size} bytes")
    print(f"Version:         {version!r}")
    print(f"Partition count: {partition_count}")

    total_regions = 0
    for i in range(partition_count):
        pid = read_ref()
        outputs_json = read_ref()
        regex = read_ref()
        region_count = read("<H")
        total_regions += region_count
        copies = 0
        overrides = 0
        for _ in range(region_count):
            read_ref()  # name
            has_override = read("<B")
            if has_override:
                read_ref()  # merged outputs json
                overrides += 1
            else:
                copies += 1
        print(f"  [{i}] id={pid!r} regions={region_count} copies={copies} overrides={overrides} regex={regex!r}")

    print(f"Total regions:   {total_regions}")
    print(f"Total size:      {len(data)} bytes")


def main():
    if "--verify" in sys.argv:
        args = [a for a in sys.argv[1:] if a != "--verify"]
        if not args:
            print(f"Usage: {sys.argv[0]} --verify <file.bin>", file=sys.stderr)
            sys.exit(1)
        verify(args[0])
        return

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.bin>", file=sys.stderr)
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path) as f:
        data = json.load(f)

    strings = StringBlob()
    bytecode = compile_partitions(data, strings)

    with open(output_path, "wb") as f:
        f.write(bytecode)

    print(f"Wrote {len(bytecode)} bytes to {output_path}")


if __name__ == "__main__":
    main()
