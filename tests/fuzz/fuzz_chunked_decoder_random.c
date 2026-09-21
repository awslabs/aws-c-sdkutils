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

    struct aws_allocator *allocator = aws_mem_tracer_new(aws_default_allocator(), NULL, AWS_MEMTRACE_BYTES, 0);

    aws_sdkutils_library_init(allocator);

    struct aws_chunked_decoder_options options = {
        .allocator = allocator,
        .on_trailer = s_on_trailer,
    };
    struct aws_chunked_decoder *decoder = aws_chunked_decoder_new(&options);

    struct aws_byte_buf output;
    aws_byte_buf_init(&output, allocator, size);

    /* Feed entire input at once */
    struct aws_byte_cursor input = aws_byte_cursor_from_array(data, size);
    aws_chunked_decoder_process(decoder, input, &output);

    aws_byte_buf_clean_up(&output);
    aws_chunked_decoder_destroy(decoder);

    ASSERT_UINT_EQUALS(0, aws_mem_tracer_count(allocator));
    aws_mem_tracer_destroy(allocator);

    return 0;
}

AWS_EXTERN_C_END
