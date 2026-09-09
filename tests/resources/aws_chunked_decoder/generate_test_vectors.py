#!/usr/bin/env python3
"""Generate C test vectors from aws_chunked_decode_tests.json"""

import json
import sys
import os


def escape_c_string(s):
    """Escape a string for C string literal, handling \\r\\n specially."""
    result = []
    for ch in s:
        if ch == '\r':
            result.append('\\r')
        elif ch == '\n':
            result.append('\\n')
        elif ch == '"':
            result.append('\\"')
        elif ch == '\\':
            result.append('\\\\')
        else:
            result.append(ch)
    return ''.join(result)


def main():
    if len(sys.argv) < 2:
        script = os.path.basename(sys.argv[0])
        print(f"Usage: {script} <json_file>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)

    print("/* Auto-generated from aws_chunked_decode_tests.json — do not edit */")
    print()

    # Success vectors
    print("static struct test_vector s_success_vectors[] = {")
    for v in data["success_tests"]:
        inp = escape_c_string(v["input"])
        out = escape_c_string(v["expect"]["output"])
        desc = escape_c_string(v["description"])
        decoded_len = v.get("expected_decoded_length", 0)
        trailers = v["expect"]["trailers"]
        print(f"    {{")
        print(f"        .description = \"{desc}\",")
        print(f"        .input = \"{inp}\",")
        print(f"        .expected_output = \"{out}\",")
        print(f"        .expected_decoded_length = {decoded_len},")
        print(f"        .num_trailers = {len(trailers)},")
        if trailers:
            print(f"        .expected_trailers = {{")
            for t in trailers:
                name = escape_c_string(t["name"])
                value = escape_c_string(t["value"])
                print(f"            {{\"{name}\", \"{value}\"}},")
            print(f"        }},")
        else:
            print(f"        .expected_trailers = {{{{0}}}},")
        print(f"    }},")
    print("};")
    print()

    # Error vectors
    print("static struct error_vector s_error_vectors[] = {")
    for v in data["error_tests"]:
        inp = escape_c_string(v["input"])
        desc = escape_c_string(v["description"])
        decoded_len = v.get("expected_decoded_length", 0)
        print(f"    {{")
        print(f"        .description = \"{desc}\",")
        print(f"        .input = \"{inp}\",")
        print(f"        .expected_decoded_length = {decoded_len},")
        print(f"    }},")
    print("};")
    print()
    print(
        f"#define NUM_SUCCESS_VECTORS (sizeof(s_success_vectors) / sizeof(s_success_vectors[0]))")
    print(
        f"#define NUM_ERROR_VECTORS (sizeof(s_error_vectors) / sizeof(s_error_vectors[0]))")


if __name__ == "__main__":
    main()
