/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/aws_chunked_decoder.h>
#include <aws/sdkutils/sdkutils.h>

#include <aws/common/allocator.h>
#include <aws/testing/aws_test_harness.h>

static int s_on_trailer(struct aws_byte_cursor name, struct aws_byte_cursor value, void *user_data) {
    (void)name;
    (void)value;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

AWS_EXTERN_C_BEGIN

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size < 2) {
        return 0;
    }

    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);

    aws_sdkutils_library_init(allocator);

    struct aws_chunked_decoder_options options = {
        .allocator = allocator,
        .on_trailer = s_on_trailer,
    };
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, size);

    /* First byte determines chunk size for splitting (1-255) */
    size_t chunk_size = (size_t)(data[0]);
    if (chunk_size == 0) {
        chunk_size = 1;
    }

    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;
    size_t offset = 0;

    while (offset < payload_size) {
        size_t piece_len = payload_size - offset;
        if (piece_len > chunk_size) {
            piece_len = chunk_size;
        }
        struct aws_byte_cursor piece = aws_byte_cursor_from_array(payload + offset, piece_len);
        if (aws_chunked_decoder_process(decoder, piece, &output) != AWS_OP_SUCCESS) {
            break;
        }
        offset += piece_len;
    }

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);

    ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
    aws_mem_tracer_destroy(allocator);

    return 0;
}

AWS_EXTERN_C_END
