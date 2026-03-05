#!/usr/bin/env python3
"""BDD bytecode compiler: JSON -> binary bytecode with concatenated string blob."""

import json
import struct
import sys

MAGIC = 0x45504452


class StringBlob:
    """Collects unique strings into one concatenated blob; returns (offset, length) pairs."""

    def __init__(self):
        self._blob = bytearray()
        self._index = {}  # str -> (offset, length)

    def add(self, s):
        if not s:
            return (0, 0)
        if s not in self._index:
            encoded = s.encode("utf-8")
            offset = len(self._blob)
            if offset > 0xFFFF:
                raise ValueError(f"String blob offset {offset} exceeds uint16 max")
            self._blob.extend(encoded)
            self._index[s] = (offset, len(encoded))
        return self._index[s]

    def blob(self):
        return bytes(self._blob)


def write_string_ref(buf, offset, length):
    """Emit 4 bytes: uint16 offset + uint16 length into buf (mutates in-place)."""
    buf.extend(struct.pack("<HH", offset, length))


def collect_strings(data, strings):
    """Pre-pass: register every string from the JSON into the StringBlob."""
    v = data.get("version")
    if v:
        strings.add(v)
    for name, p in data.get("parameters", {}).items():
        strings.add(name)
        if p.get("builtIn"):
            strings.add(p["builtIn"])
        dv = p.get("default")
        if isinstance(dv, str):
            strings.add(dv)
    for c in data.get("conditions", []):
        strings.add(c["fn"])
        if "assign" in c:
            strings.add(c["assign"])
        for arg in c.get("argv", []):
            _collect_value_strings(arg, strings)
    for r in data.get("results", []):
        if "endpoint" in r:
            ep = r["endpoint"]
            strings.add(ep.get("url", ""))
            for k, v in ep.get("properties", {}).items():
                strings.add(k)
                _collect_value_strings(v, strings)
        elif "error" in r:
            strings.add(r["error"])


def _collect_value_strings(val, strings):
    if isinstance(val, str):
        strings.add(val)
    elif isinstance(val, dict):
        for k, v in val.items():
            strings.add(k)
            _collect_value_strings(v, strings)
    elif isinstance(val, list):
        for v in val:
            _collect_value_strings(v, strings)


def encode_parameters(buf, data, strings):
    """Emit parameter count (uint16) then each parameter record."""
    params = data.get("parameters", {})
    buf += struct.pack("<H", len(params))
    for name, p in params.items():
        ptype = p.get("type", "string").lower()
        opcode = 0x01 if ptype == "string" else 0x02
        buf += struct.pack("<B", opcode)
        write_string_ref(buf, *strings.add(name))
        dv = p.get("default")
        has_default = dv is not None
        buf += struct.pack("<B", 1 if has_default else 0)
        if has_default:
            if opcode == 0x01:
                write_string_ref(buf, *strings.add(dv))
            else:
                buf += struct.pack("<B", 1 if dv else 0)
        buf += struct.pack("<B", 1 if p.get("required") else 0)
        built_in = p.get("builtIn")
        buf += struct.pack("<B", 1 if built_in else 0)
        if built_in:
            write_string_ref(buf, *strings.add(built_in))


def encode_value(buf, val, strings):
    """Recursively encode a value with type tag (0-7)."""
    if val is None:
        buf += struct.pack("<B", 0)
    elif isinstance(val, bool):
        buf += struct.pack("<BB", 2, 1 if val else 0)
    elif isinstance(val, str):
        buf += struct.pack("<B", 1)
        write_string_ref(buf, *strings.add(val))
    elif isinstance(val, int):
        buf += struct.pack("<Bi", 3, val)
    elif isinstance(val, dict) and "ref" in val:
        buf += struct.pack("<B", 4)
        write_string_ref(buf, *strings.add(val["ref"]))
    elif isinstance(val, dict) and "fn" in val:
        buf += struct.pack("<B", 5)
        write_string_ref(buf, *strings.add(val["fn"]))
        args = val.get("argv", [])
        buf += struct.pack("<H", len(args))
        for a in args:
            encode_value(buf, a, strings)
    elif isinstance(val, list):
        buf += struct.pack("<BH", 6, len(val))
        for item in val:
            encode_value(buf, item, strings)
    elif isinstance(val, dict):
        buf += struct.pack("<BH", 7, len(val))
        for k, v in val.items():
            write_string_ref(buf, *strings.add(k))
            encode_value(buf, v, strings)
    else:
        buf += struct.pack("<B", 0)


def encode_conditions(buf, data, strings):
    """Emit condition count (uint16) then each condition record."""
    conditions = data.get("conditions", [])
    buf += struct.pack("<H", len(conditions))
    for c in conditions:
        buf += struct.pack("<B", 0x10)
        write_string_ref(buf, *strings.add(c["fn"]))
        args = c.get("argv", [])
        buf += struct.pack("<H", len(args))
        for a in args:
            encode_value(buf, a, strings)
        assign = c.get("assign")
        buf += struct.pack("<B", 1 if assign else 0)
        if assign:
            write_string_ref(buf, *strings.add(assign))


def encode_results(buf, data, strings):
    """Emit result count (uint16) then each result record. Index 0 = NoMatchRule (implicit), so first serialized result maps to index 1."""
    results = data.get("results", [])
    buf += struct.pack("<H", len(results))
    for r in results:
        if "endpoint" in r:
            ep = r["endpoint"]
            buf += struct.pack("<B", 0x20)
            write_string_ref(buf, *strings.add(ep.get("url", "")))
            props = ep.get("properties", {})
            buf += struct.pack("<H", len(props))
            for k, v in props.items():
                write_string_ref(buf, *strings.add(k))
                encode_value(buf, v, strings)
        elif "error" in r:
            buf += struct.pack("<B", 0x21)
            write_string_ref(buf, *strings.add(r["error"]))


def encode_nodes(buf, data):
    """Emit root_ref (int32), node_count (uint32), then the base64 nodes blob with uint16 length prefix."""
    root_ref = data.get("root", 0)
    node_count = data.get("nodeCount", 0)
    buf += struct.pack("<iI", root_ref, node_count)
    nodes_b64 = data.get("nodes", "")
    encoded = nodes_b64.encode("ascii")
    buf += struct.pack("<H", len(encoded))
    buf += encoded


def encode(data, strings):
    """Encoding pass: produce the full bytecode bytes."""
    buf = bytearray()
    # Magic
    buf += struct.pack("<I", MAGIC)
    # String blob section (must come before any string refs)
    blob = strings.blob()
    buf += struct.pack("<I", len(blob))
    buf += blob
    # Version string ref
    v = data.get("version")
    off, ln = strings.add(v) if v else (0, 0)
    write_string_ref(buf, off, ln)
    # Parameters section
    encode_parameters(buf, data, strings)
    # Conditions section
    encode_conditions(buf, data, strings)
    # Results section
    encode_results(buf, data, strings)
    # Nodes section
    encode_nodes(buf, data)
    return bytes(buf)


def verify(bin_path):
    """Read a compiled .bin file and print a human-readable summary."""
    with open(bin_path, "rb") as f:
        data = f.read()
    pos = 0

    def read(fmt):
        nonlocal pos
        size = struct.calcsize(fmt)
        val = struct.unpack_from(fmt, data, pos)
        pos += size
        return val[0] if len(val) == 1 else val

    try:
        magic = read("<I")
        if magic != MAGIC:
            print(f"ERROR: bad magic 0x{magic:08X} (expected 0x{MAGIC:08X})", file=sys.stderr)
            sys.exit(1)

        blob_size = read("<I")
        blob = data[pos:pos + blob_size]
        pos += blob_size

        string_refs = set()

        def track_ref():
            nonlocal pos
            off, ln = struct.unpack_from("<HH", data, pos)
            pos += 4
            if ln > 0:
                string_refs.add((off, ln))

        # Version string ref
        v_off, v_len = read("<HH")
        if v_len > 0:
            string_refs.add((v_off, v_len))
        version_str = blob[v_off:v_off + v_len].decode("utf-8") if v_len else ""

        # Parameters
        param_count = read("<H")
        for _ in range(param_count):
            opcode = read("<B")
            track_ref()  # name
            has_def = read("<B")
            if has_def:
                if opcode == 0x01:
                    track_ref()
                else:
                    pos += 1
            pos += 1  # required
            has_bi = read("<B")
            if has_bi:
                track_ref()  # built_in ref

        # Conditions
        cond_count = read("<H")

        def skip_value():
            nonlocal pos
            tag = read("<B")
            if tag == 0:
                pass
            elif tag == 1:
                track_ref()
            elif tag == 2:
                pos += 1
            elif tag == 3:
                pos += 4
            elif tag == 4:
                track_ref()
            elif tag == 5:
                track_ref()
                argc = read("<H")
                for _ in range(argc):
                    skip_value()
            elif tag == 6:
                n = read("<H")
                for _ in range(n):
                    skip_value()
            elif tag == 7:
                n = read("<H")
                for _ in range(n):
                    track_ref()
                    skip_value()

        for _ in range(cond_count):
            pos += 1  # opcode
            track_ref()  # fn ref
            argc = read("<H")
            for _ in range(argc):
                skip_value()
            has_assign = read("<B")
            if has_assign:
                track_ref()

        # Results
        result_count = read("<H")
        for _ in range(result_count):
            opcode = read("<B")
            if opcode == 0x20:
                track_ref()  # url ref
                prop_count = read("<H")
                for _ in range(prop_count):
                    track_ref()  # key ref
                    skip_value()
            elif opcode == 0x21:
                track_ref()  # error ref

        # Nodes
        root_ref, node_count = read("<iI")
        nodes_len = read("<H")

    except struct.error:
        print(f"ERROR: file truncated at offset {pos}", file=sys.stderr)
        sys.exit(1)

    print(f"Magic:       0x{magic:08X}")
    print(f"Blob size:   {blob_size} bytes")
    print(f"Strings:     {len(string_refs)}")
    print(f"Version:     {version_str!r}")
    print(f"Parameters:  {param_count}")
    print(f"Conditions:  {cond_count}")
    print(f"Results:     {result_count}")
    print(f"Node count:  {node_count}")
    print(f"Root ref:    {root_ref}")
    print(f"Nodes blob:  {nodes_len} bytes (base64)")
    print(f"Total size:  {len(data)} bytes")


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

    # String collection pass
    collect_strings(data, strings)

    # Encoding pass
    bytecode = encode(data, strings)

    with open(output_path, "wb") as f:
        f.write(bytecode)

    print(f"Wrote {len(bytecode)} bytes to {output_path}")


if __name__ == "__main__":
    main()
