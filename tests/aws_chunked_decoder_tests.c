/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/aws_chunked_decoder.h>
#include <aws/testing/aws_test_harness.h>

/* === Standalone tests (behavior not covered by data-driven vectors) === */

AWS_TEST_CASE(aws_chunked_decoder_new_destroy, s_test_new_destroy)
static int s_test_new_destroy(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {
        .allocator = allocator,
    };

    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);
    ASSERT_NOT_NULL(decoder);
    ASSERT_FALSE(aws_chunked_decoder_is_done(decoder));

    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_chunked_decoder_process_empty_input, s_test_process_empty_input)
static int s_test_process_empty_input(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {.allocator = allocator};
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("");
    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 64);

    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, input, &output));
    ASSERT_UINT_EQUALS(0, output.len);
    ASSERT_FALSE(aws_chunked_decoder_is_done(decoder));

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

/* Tests that error state is permanent across calls */
AWS_TEST_CASE(aws_chunked_decoder_permanent_error, s_test_permanent_error)
static int s_test_permanent_error(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {.allocator = allocator};
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 64);

    struct aws_byte_cursor bad = aws_byte_cursor_from_c_str("ZZ;chunk-signature=UNSIGNED-PAYLOAD\r\n");
    ASSERT_FAILS(aws_chunked_decoder_process(decoder, bad, &output));

    /* Subsequent calls with valid input should also fail */
    struct aws_byte_cursor good = aws_byte_cursor_from_c_str("5;chunk-signature=UNSIGNED-PAYLOAD\r\n");
    ASSERT_FAILS(aws_chunked_decoder_process(decoder, good, &output));

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

/* Tests scratch buffer with partial chunk-size line */
AWS_TEST_CASE(aws_chunked_decoder_partial_line_split, s_test_partial_line_split)
static int s_test_partial_line_split(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {.allocator = allocator};
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 64);

    struct aws_byte_cursor part1 = aws_byte_cursor_from_c_str("5;chunk-sig");
    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, part1, &output));

    struct aws_byte_cursor part2 = aws_byte_cursor_from_c_str("nature=UNSIGNED-PAYLOAD\r\n");
    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, part2, &output));

    /* Verify decoder parsed size=5 by feeding data bytes */
    struct aws_byte_cursor data = aws_byte_cursor_from_c_str("hello");
    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, data, &output));
    ASSERT_UINT_EQUALS(5, output.len);

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

/* Tests max line length cap */
AWS_TEST_CASE(aws_chunked_decoder_line_too_long, s_test_line_too_long)
static int s_test_line_too_long(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {.allocator = allocator};
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 64);

    char long_line[1100];
    memset(long_line, 'A', sizeof(long_line));
    struct aws_byte_cursor input = {.ptr = (uint8_t *)long_line, .len = sizeof(long_line)};
    ASSERT_FAILS(aws_chunked_decoder_process(decoder, input, &output));

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

/* Tests split within chunk data bytes */
AWS_TEST_CASE(aws_chunked_decoder_split_mid_data, s_test_split_mid_data)
static int s_test_split_mid_data(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {.allocator = allocator};
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 64);

    struct aws_byte_cursor part1 = aws_byte_cursor_from_c_str("5;chunk-signature=UNSIGNED-PAYLOAD\r\n");
    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, part1, &output));

    struct aws_byte_cursor part2 = aws_byte_cursor_from_c_str("hel");
    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, part2, &output));
    ASSERT_UINT_EQUALS(3, output.len);

    struct aws_byte_cursor part3 = aws_byte_cursor_from_c_str("lo\r\n0;chunk-signature=UNSIGNED-PAYLOAD\r\n");
    ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, part3, &output));
    ASSERT_UINT_EQUALS(5, output.len);
    ASSERT_BIN_ARRAYS_EQUALS("hello", 5, output.buffer, output.len);

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

/* Tests that on_trailer callback error propagates */
static int s_error_trailer(struct aws_byte_cursor name, struct aws_byte_cursor value, void *user_data) {
    (void)name;
    (void)value;
    (void)user_data;
    return aws_raise_error(AWS_ERROR_UNKNOWN);
}

AWS_TEST_CASE(aws_chunked_decoder_callback_error, s_test_callback_error)
static int s_test_callback_error(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_chunked_decoder_options options = {.allocator = allocator, .on_trailer = s_error_trailer};
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 64);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("0;chunk-signature=UNSIGNED-PAYLOAD\r\n"
                                                              "x-amz-wire-checksum-crc32:abc==\r\n"
                                                              "\r\n");
    ASSERT_FAILS(aws_chunked_decoder_process(decoder, input, &output));

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

/* === Data-driven test harness === */

struct trailer_capture {
    struct aws_byte_buf names[4];
    struct aws_byte_buf values[4];
    int call_count;
};

static int s_capture_trailer(struct aws_byte_cursor name, struct aws_byte_cursor value, void *user_data) {
    struct trailer_capture *cap = user_data;
    int i = cap->call_count;
    aws_byte_buf_append_dynamic(&cap->names[i], &name);
    aws_byte_buf_append_dynamic(&cap->values[i], &value);
    cap->call_count++;
    return AWS_OP_SUCCESS;
}

struct expected_trailer {
    const char *name;
    const char *value;
};

struct test_vector {
    const char *description;
    const char *input;
    const char *expected_output;
    uint64_t expected_decoded_length;
    int num_trailers;
    struct expected_trailer expected_trailers[4];
};

struct error_vector {
    const char *description;
    const char *input;
    uint64_t expected_decoded_length;
};

#include "aws_chunked_decoder_test_vectors.inc"

static int s_run_vector_with_split(struct aws_allocator *allocator, struct test_vector *vector, size_t split_size) {

    struct trailer_capture cap;
    AWS_ZERO_STRUCT(cap);
    for (int i = 0; i < 4; ++i) {
        aws_byte_buf_init(&cap.names[i], allocator, 64);
        aws_byte_buf_init(&cap.values[i], allocator, 64);
    }

    struct aws_chunked_decoder_options options = {
        .allocator = allocator,
        .on_trailer = s_capture_trailer,
        .user_data = &cap,
        .expected_content_length = &vector->expected_decoded_length,
    };
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, 256);

    struct aws_byte_cursor remaining = aws_byte_cursor_from_c_str(vector->input);

    while (remaining.len > 0) {
        size_t chunk = remaining.len;
        if (split_size > 0 && chunk > split_size) {
            chunk = split_size;
        }
        struct aws_byte_cursor piece = {.ptr = remaining.ptr, .len = chunk};
        ASSERT_SUCCESS(aws_chunked_decoder_process(decoder, piece, &output));
        aws_byte_cursor_advance(&remaining, chunk);
    }

    ASSERT_TRUE(aws_chunked_decoder_is_done(decoder));

    size_t expected_len = strlen(vector->expected_output);
    ASSERT_UINT_EQUALS(expected_len, output.len);
    ASSERT_BIN_ARRAYS_EQUALS(vector->expected_output, expected_len, output.buffer, output.len);

    ASSERT_INT_EQUALS(vector->num_trailers, cap.call_count);
    for (int i = 0; i < vector->num_trailers; ++i) {
        size_t name_len = strlen(vector->expected_trailers[i].name);
        ASSERT_BIN_ARRAYS_EQUALS(vector->expected_trailers[i].name, name_len, cap.names[i].buffer, cap.names[i].len);
        size_t value_len = strlen(vector->expected_trailers[i].value);
        ASSERT_BIN_ARRAYS_EQUALS(
            vector->expected_trailers[i].value, value_len, cap.values[i].buffer, cap.values[i].len);
    }

    aws_byte_buf_clean_up(&output);
    for (int i = 0; i < 4; ++i) {
        aws_byte_buf_clean_up(&cap.names[i]);
        aws_byte_buf_clean_up(&cap.values[i]);
    }
    aws_chunked_decoder_destroy(decoder);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_chunked_decoder_split_all_at_once, s_test_split_all_at_once)
static int s_test_split_all_at_once(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < NUM_SUCCESS_VECTORS; ++i) {
        ASSERT_SUCCESS(s_run_vector_with_split(allocator, &s_success_vectors[i], 0));
    }
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_chunked_decoder_split_one_byte, s_test_split_one_byte)
static int s_test_split_one_byte(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < NUM_SUCCESS_VECTORS; ++i) {
        ASSERT_SUCCESS(s_run_vector_with_split(allocator, &s_success_vectors[i], 1));
    }
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_chunked_decoder_split_two_bytes, s_test_split_two_bytes)
static int s_test_split_two_bytes(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < NUM_SUCCESS_VECTORS; ++i) {
        ASSERT_SUCCESS(s_run_vector_with_split(allocator, &s_success_vectors[i], 2));
    }
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_chunked_decoder_error_vectors, s_test_error_vectors)
static int s_test_error_vectors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < NUM_ERROR_VECTORS; ++i) {
        /* Only set expected_content_length if the vector has a non-zero value
         * (0 means "not specified" for error vectors that don't test length mismatch) */
        const uint64_t *expected_len = NULL;
        if (s_error_vectors[i].expected_decoded_length > 0) {
            expected_len = &s_error_vectors[i].expected_decoded_length;
        }
        struct aws_chunked_decoder_options options = {
            .allocator = allocator,
            .expected_content_length = expected_len,
        };
        struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

        struct aws_byte_buf output;
        aws_byte_buf_init(&output, allocator, 64);

        struct aws_byte_cursor input = aws_byte_cursor_from_c_str(s_error_vectors[i].input);
        ASSERT_FAILS(aws_chunked_decoder_process(decoder, input, &output));

        aws_byte_buf_clean_up(&output);
        aws_chunked_decoder_destroy(decoder);
    }
    return AWS_OP_SUCCESS;
}
