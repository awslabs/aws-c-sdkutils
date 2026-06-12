/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef AWS_SDKUTILS_AWS_CHUNKED_DECODER_H
#define AWS_SDKUTILS_AWS_CHUNKED_DECODER_H

#include <aws/sdkutils/sdkutils.h>

#include <aws/common/byte_buf.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_chunked_decoder;

/**
 * Callback invoked once per trailer parsed (may be called multiple times if multiple trailers present).
 * name and value are cursors into internal scratch memory — caller must copy if needed beyond this call.
 * Return AWS_OP_SUCCESS to continue, or AWS_OP_ERR to abort decoding.
 */
typedef int(
    aws_chunked_decoder_on_trailer_fn)(struct aws_byte_cursor name, struct aws_byte_cursor value, void *user_data);

struct aws_chunked_decoder_options {
    struct aws_allocator *allocator;
    aws_chunked_decoder_on_trailer_fn *on_trailer;
    void *user_data;
    /* Required. The decoder verifies that the total decoded byte count matches this value when the
     * terminal chunk is reached, raising AWS_ERROR_SDKUTILS_PARSE_FATAL on mismatch (truncation). */
    uint64_t expected_content_length;
};

AWS_EXTERN_C_BEGIN

/**
 * Create a new aws-chunked decoder.
 */
AWS_SDKUTILS_API
struct aws_chunked_decoder *aws_chunked_decoder_new(const struct aws_chunked_decoder_options *options);

/**
 * Destroy the decoder and free all internal resources.
 */
AWS_SDKUTILS_API
void aws_chunked_decoder_destroy(struct aws_chunked_decoder *decoder);

/**
 * Feed input bytes into the decoder. Decoded data bytes are appended to output_buf.
 *
 * Returns AWS_OP_SUCCESS on success, AWS_OP_ERR on malformed input.
 * On error, the decoder enters a permanent error state.
 */
AWS_SDKUTILS_API
int aws_chunked_decoder_process(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor input,
    struct aws_byte_buf *output_buf);

/**
 * Returns true if the decoder has finished processing (terminal chunk + trailer parsed).
 */
AWS_SDKUTILS_API
bool aws_chunked_decoder_is_done(const struct aws_chunked_decoder *decoder);

/**
 * Returns the expected (decoded) content length the decoder was configured with.
 */
AWS_SDKUTILS_API
uint64_t aws_chunked_decoder_get_expected_content_length(const struct aws_chunked_decoder *decoder);

/**
 * Returns the number of decoded payload bytes produced so far (across all process() calls).
 * At successful completion this equals the expected content length.
 */
AWS_SDKUTILS_API
uint64_t aws_chunked_decoder_get_decoded_length(const struct aws_chunked_decoder *decoder);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_SDKUTILS_AWS_CHUNKED_DECODER_H */
