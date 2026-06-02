/* Auto-generated from aws_chunked_decode_tests.json — do not edit */

static struct test_vector s_success_vectors[] = {
    {
        .description = "single chunk with trailer",
        .input = "5;chunk-signature=UNSIGNED-PAYLOAD\r\nhello\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:abc123==\r\n\r\n",
        .expected_output = "hello",
        .expected_decoded_length = 5,
        .num_trailers = 1,
        .expected_trailers = {
            {"trailer-key", "abc123=="},
        },
    },
    {
        .description = "multiple chunks with trailer",
        .input = "5;chunk-signature=UNSIGNED-PAYLOAD\r\nhello\r\n6;chunk-signature=UNSIGNED-PAYLOAD\r\n world\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:AAAA==\r\n\r\n",
        .expected_output = "hello world",
        .expected_decoded_length = 11,
        .num_trailers = 1,
        .expected_trailers = {
            {"trailer-key", "AAAA=="},
        },
    },
    {
        .description = "single byte chunk",
        .input = "1;chunk-signature=UNSIGNED-PAYLOAD\r\nX\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:ZZ==\r\n\r\n",
        .expected_output = "X",
        .expected_decoded_length = 1,
        .num_trailers = 1,
        .expected_trailers = {
            {"trailer-key", "ZZ=="},
        },
    },
    {
        .description = "large chunk size (multi-digit hex, 0x1a = 26 bytes)",
        .input = "1a;chunk-signature=UNSIGNED-PAYLOAD\r\nabcdefghijklmnopqrstuvwxyz\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:base64value==\r\n\r\n",
        .expected_output = "abcdefghijklmnopqrstuvwxyz",
        .expected_decoded_length = 26,
        .num_trailers = 1,
        .expected_trailers = {
            {"trailer-key", "base64value=="},
        },
    },
    {
        .description = "trailer value with leading/trailing whitespace (should be trimmed)",
        .input = "3;chunk-signature=UNSIGNED-PAYLOAD\r\nfoo\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:  abc123==  \r\n\r\n",
        .expected_output = "foo",
        .expected_decoded_length = 3,
        .num_trailers = 1,
        .expected_trailers = {
            {"trailer-key", "abc123=="},
        },
    },
    {
        .description = "varying chunk-signature values (forward compatibility)",
        .input = "3;chunk-signature=some-future-value\r\nbar\r\n0;chunk-signature=another-value\r\ntrailer-key:xyz==\r\n\r\n",
        .expected_output = "bar",
        .expected_decoded_length = 3,
        .num_trailers = 1,
        .expected_trailers = {
            {"trailer-key", "xyz=="},
        },
    },
    {
        .description = "multiple trailers",
        .input = "5;chunk-signature=UNSIGNED-PAYLOAD\r\nhello\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\nfirst-trailer:value1\r\nsecond-trailer:value2\r\n\r\n",
        .expected_output = "hello",
        .expected_decoded_length = 5,
        .num_trailers = 2,
        .expected_trailers = {
            {"first-trailer", "value1"},
            {"second-trailer", "value2"},
        },
    },
};

static struct error_vector s_error_vectors[] = {
    {
        .description = "invalid hex in chunk size",
        .input = "ZZ;chunk-signature=UNSIGNED-PAYLOAD\r\n",
        .expected_decoded_length = 0,
    },
    {
        .description = "missing CRLF after chunk data",
        .input = "3;chunk-signature=UNSIGNED-PAYLOAD\r\nfooX",
        .expected_decoded_length = 0,
    },
    {
        .description = "malformed trailer (no colon separator)",
        .input = "0;chunk-signature=UNSIGNED-PAYLOAD\r\nnot-a-valid-trailer\r\n",
        .expected_decoded_length = 0,
    },
    {
        .description = "data after terminal chunk and trailer (extra bytes after DONE)",
        .input = "3;chunk-signature=UNSIGNED-PAYLOAD\r\nfoo\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:abc==\r\n\r\nextra garbage",
        .expected_decoded_length = 0,
    },
    {
        .description = "decoded content length mismatch (expected 100, actual 5)",
        .input = "5;chunk-signature=UNSIGNED-PAYLOAD\r\nhello\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\ntrailer-key:abc==\r\n\r\n",
        .expected_decoded_length = 100,
    },
};

#define NUM_SUCCESS_VECTORS (sizeof(s_success_vectors) / sizeof(s_success_vectors[0]))
#define NUM_ERROR_VECTORS (sizeof(s_error_vectors) / sizeof(s_error_vectors[0]))
