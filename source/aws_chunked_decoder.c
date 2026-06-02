/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/aws_chunked_decoder.h>

#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>

#define AWS_CHUNKED_DECODER_MAX_LINE_LENGTH 1024

typedef int(aws_chunked_decoder_state_fn)(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf);

struct aws_chunked_decoder {
    struct aws_allocator *alloc;

    /* State machine */
    aws_chunked_decoder_state_fn *state;

    /* Scratch buffer for partial metadata lines */
    struct aws_byte_buf scratch;

    /* Current chunk tracking */
    uint64_t chunk_size;
    uint64_t chunk_processed;

    /* Total decoded bytes tracking */
    uint64_t total_decoded;
    uint64_t expected_content_length;

    /* Trailer callback */
    aws_chunked_decoder_on_trailer_fn *on_trailer;
    void *user_data;

    /* Flags */
    bool is_done;
    bool has_error;
};

/* Forward declarations */
static int s_state_chunk_size_line(struct aws_chunked_decoder *decoder, struct aws_byte_cursor *input, struct aws_byte_buf *output_buf);
static int s_state_chunk_data(struct aws_chunked_decoder *decoder, struct aws_byte_cursor *input, struct aws_byte_buf *output_buf);
static int s_state_chunk_data_crlf(struct aws_chunked_decoder *decoder, struct aws_byte_cursor *input, struct aws_byte_buf *output_buf);
static int s_state_trailer_line(struct aws_chunked_decoder *decoder, struct aws_byte_cursor *input, struct aws_byte_buf *output_buf);
static int s_state_done(struct aws_chunked_decoder *decoder, struct aws_byte_cursor *input, struct aws_byte_buf *output_buf);

/* Append to scratch, using reserve to grow if needed. Returns error if max length exceeded. */
static int s_scratch_append(struct aws_chunked_decoder *decoder, struct aws_byte_cursor data) {
    size_t new_len = decoder->scratch.len + data.len;
    if (new_len > AWS_CHUNKED_DECODER_MAX_LINE_LENGTH) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }
    if (decoder->scratch.capacity == 0) {
        aws_byte_buf_init(&decoder->scratch, decoder->alloc, new_len);
    } else {
        aws_byte_buf_reserve(&decoder->scratch, new_len);
    }
    return aws_byte_buf_append_dynamic(&decoder->scratch, &data);
}

/* Find CRLF in cursor. Returns position past \n, or 0 if not found. */
static size_t s_find_crlf(struct aws_byte_cursor input) {
    struct aws_byte_cursor crlf = aws_byte_cursor_from_c_str("\r\n");
    struct aws_byte_cursor found;
    if (aws_byte_cursor_find_exact(&input, &crlf, &found) == AWS_OP_SUCCESS) {
        /* found.ptr points to '\r', so position past '\n' is: */
        return (size_t)(found.ptr - input.ptr) + 2;
    }
    return 0;
}

static int s_state_chunk_size_line(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    (void)output_buf;

    /* Check if \r might be at end of scratch from previous call */
    bool cr_in_scratch = decoder->scratch.len > 0 &&
                         decoder->scratch.buffer[decoder->scratch.len - 1] == '\r';

    /* If scratch ends with \r and input starts with \n, we found the CRLF */
    if (cr_in_scratch && input->len > 0 && input->ptr[0] == '\n') {
        aws_byte_cursor_advance(input, 1);
        /* Remove trailing \r from scratch */
        decoder->scratch.len -= 1;
        goto process_line;
    }

    /* Scan input for CRLF */
    size_t crlf_pos = s_find_crlf(*input);
    if (crlf_pos > 0) {
        /* Found CRLF in input */
        struct aws_byte_cursor before_crlf = aws_byte_cursor_advance(input, crlf_pos);
        /* Strip the \r\n (last 2 bytes of before_crlf) */
        before_crlf.len -= 2;

        if (decoder->scratch.len > 0) {
            /* Append what's before CRLF to scratch, then process scratch */
            if (s_scratch_append(decoder, before_crlf)) {
                return AWS_OP_ERR;
            }
            goto process_line;
        }

        /* No scratch — process directly from input */
        struct aws_byte_cursor line = before_crlf;
        /* Split on ';' to get hex size */
        struct aws_byte_cursor hex_part = line;
        for (size_t i = 0; i < line.len; ++i) {
            if (line.ptr[i] == ';') {
                hex_part.len = i;
                break;
            }
        }

        uint64_t size = 0;
        if (aws_byte_cursor_utf8_parse_u64_hex(hex_part, &size)) {
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }

        if (size == 0) {
            if (decoder->expected_content_length > 0 &&
                decoder->total_decoded != decoder->expected_content_length) {
                return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
            }
            decoder->state = s_state_trailer_line;
        } else {
            decoder->chunk_size = size;
            decoder->chunk_processed = 0;
            decoder->state = s_state_chunk_data;
        }
        return AWS_OP_SUCCESS;
    }

    /* No CRLF found — buffer everything and wait for more data */
    if (s_scratch_append(decoder, *input)) {
        return AWS_OP_ERR;
    }
    input->ptr += input->len;
    input->len = 0;
    return AWS_OP_SUCCESS;

process_line:
    /* Process the complete line from scratch buffer */
    {
        struct aws_byte_cursor line = aws_byte_cursor_from_buf(&decoder->scratch);
        /* Split on ';' */
        struct aws_byte_cursor hex_part = line;
        for (size_t i = 0; i < line.len; ++i) {
            if (line.ptr[i] == ';') {
                hex_part.len = i;
                break;
            }
        }

        uint64_t size = 0;
        if (aws_byte_cursor_utf8_parse_u64_hex(hex_part, &size)) {
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }

        if (size == 0) {
            if (decoder->expected_content_length > 0 &&
                decoder->total_decoded != decoder->expected_content_length) {
                return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
            }
            decoder->state = s_state_trailer_line;
        } else {
            decoder->chunk_size = size;
            decoder->chunk_processed = 0;
            decoder->state = s_state_chunk_data;
        }

        decoder->scratch.len = 0;
        return AWS_OP_SUCCESS;
    }
}

static int s_state_chunk_data(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    uint64_t remaining = decoder->chunk_size - decoder->chunk_processed;
    size_t to_copy = input->len;
    if (to_copy > remaining) {
        to_copy = (size_t)remaining;
    }

    struct aws_byte_cursor data = aws_byte_cursor_advance(input, to_copy);
    if (aws_byte_buf_append_dynamic(output_buf, &data)) {
        return AWS_OP_ERR;
    }

    decoder->chunk_processed += to_copy;
    decoder->total_decoded += to_copy;
    if (decoder->chunk_processed == decoder->chunk_size) {
        decoder->state = s_state_chunk_data_crlf;
    }
    return AWS_OP_SUCCESS;
}

static int s_state_chunk_data_crlf(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    (void)output_buf;

    /* Handle split: \r was consumed in previous call, now expecting \n */
    if (decoder->scratch.len == 1 && decoder->scratch.buffer[0] == '\r') {
        if (input->ptr[0] != '\n') {
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }
        aws_byte_cursor_advance(input, 1);
        decoder->scratch.len = 0;
        decoder->state = s_state_chunk_size_line;
        return AWS_OP_SUCCESS;
    }

    /* Need at least 1 byte */
    if (input->len == 0) {
        return AWS_OP_SUCCESS;
    }

    if (input->ptr[0] != '\r') {
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }

    if (input->len == 1) {
        /* Only got \r, store it and wait for \n */
        struct aws_byte_cursor cr = aws_byte_cursor_advance(input, 1);
        return s_scratch_append(decoder, cr);
    }

    /* Have at least 2 bytes */
    if (input->ptr[1] != '\n') {
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }

    aws_byte_cursor_advance(input, 2);
    decoder->state = s_state_chunk_size_line;
    return AWS_OP_SUCCESS;
}

static int s_state_trailer_line(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    (void)output_buf;

    /* Handle split CRLF: scratch ends with \r, input starts with \n */
    bool cr_in_scratch = decoder->scratch.len > 0 &&
                         decoder->scratch.buffer[decoder->scratch.len - 1] == '\r';

    if (cr_in_scratch && input->len > 0 && input->ptr[0] == '\n') {
        aws_byte_cursor_advance(input, 1);
        decoder->scratch.len -= 1;
        goto process_line;
    }

    /* Scan for CRLF */
    size_t crlf_pos = s_find_crlf(*input);
    if (crlf_pos > 0) {
        struct aws_byte_cursor before_crlf = aws_byte_cursor_advance(input, crlf_pos);
        before_crlf.len -= 2;

        if (decoder->scratch.len > 0) {
            if (s_scratch_append(decoder, before_crlf)) {
                return AWS_OP_ERR;
            }
            goto process_line;
        }

        /* Process line directly from input */
        struct aws_byte_cursor line = before_crlf;
        if (line.len == 0) {
            decoder->is_done = true;
            decoder->state = s_state_done;
            return AWS_OP_SUCCESS;
        }

        /* Find colon */
        uint8_t *colon = memchr(line.ptr, ':', line.len);
        if (colon == NULL) {
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }

        struct aws_byte_cursor name = {.ptr = line.ptr, .len = (size_t)(colon - line.ptr)};
        struct aws_byte_cursor value = {.ptr = colon + 1, .len = line.len - name.len - 1};
        value = aws_byte_cursor_trim_pred(&value, aws_isspace);

        if (decoder->on_trailer) {
            if (decoder->on_trailer(name, value, decoder->user_data)) {
                return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
            }
        }
        return AWS_OP_SUCCESS;
    }

    /* No CRLF — buffer and wait */
    if (s_scratch_append(decoder, *input)) {
        return AWS_OP_ERR;
    }
    input->ptr += input->len;
    input->len = 0;
    return AWS_OP_SUCCESS;

process_line:
    {
        struct aws_byte_cursor line = aws_byte_cursor_from_buf(&decoder->scratch);
        if (line.len == 0) {
            decoder->is_done = true;
            decoder->state = s_state_done;
            decoder->scratch.len = 0;
            return AWS_OP_SUCCESS;
        }

        /* Find colon */
        uint8_t *colon = memchr(line.ptr, ':', line.len);
        if (colon == NULL) {
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }

        struct aws_byte_cursor name = {.ptr = line.ptr, .len = (size_t)(colon - line.ptr)};
        struct aws_byte_cursor value = {.ptr = colon + 1, .len = line.len - name.len - 1};
        value = aws_byte_cursor_trim_pred(&value, aws_isspace);

        if (decoder->on_trailer) {
            if (decoder->on_trailer(name, value, decoder->user_data)) {
                decoder->scratch.len = 0;
                return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
            }
        }

        decoder->scratch.len = 0;
        return AWS_OP_SUCCESS;
    }
}

static int s_state_done(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {
    (void)output_buf;
    (void)decoder;
    if (input->len > 0) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }
    return AWS_OP_SUCCESS;
}

struct aws_chunked_decoder *aws_chunked_decoder_new(
    const struct aws_chunked_decoder_options *options) {

    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->allocator);

    struct aws_chunked_decoder *decoder =
        aws_mem_calloc(options->allocator, 1, sizeof(struct aws_chunked_decoder));

    decoder->alloc = options->allocator;
    decoder->state = s_state_chunk_size_line;
    decoder->on_trailer = options->on_trailer;
    decoder->user_data = options->user_data;
    decoder->expected_content_length = options->expected_content_length;

    return decoder;
}

void aws_chunked_decoder_destroy(struct aws_chunked_decoder *decoder) {
    if (decoder == NULL) {
        return;
    }
    aws_byte_buf_clean_up(&decoder->scratch);
    aws_mem_release(decoder->alloc, decoder);
}

int aws_chunked_decoder_process(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor input,
    struct aws_byte_buf *output_buf) {

    AWS_PRECONDITION(decoder);
    AWS_PRECONDITION(output_buf);

    if (decoder->has_error) {
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }

    while (input.len > 0 && !decoder->is_done) {
        if (decoder->state(decoder, &input, output_buf)) {
            decoder->has_error = true;
            return AWS_OP_ERR;
        }
    }

    if (decoder->is_done && input.len > 0) {
        decoder->has_error = true;
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }

    return AWS_OP_SUCCESS;
}

bool aws_chunked_decoder_is_done(const struct aws_chunked_decoder *decoder) {
    AWS_PRECONDITION(decoder);
    return decoder->is_done;
}
