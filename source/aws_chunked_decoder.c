/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/sdkutils/aws_chunked_decoder.h>

#include <aws/common/byte_buf.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>

#include <inttypes.h>

#define AWS_CHUNKED_DECODER_MAX_LINE_LENGTH 1024

static const struct aws_byte_cursor s_crlf = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("\r\n");
static const uint8_t s_cr = '\r';
static const uint8_t s_lf = '\n';

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
    bool expected_content_length_set;

    /* Trailer callback */
    aws_chunked_decoder_on_trailer_fn *on_trailer;
    void *user_data;

    /* Flags */
    bool is_done;
    bool has_error;
};

/* Forward declarations */
static int s_state_chunk_size_line(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf);
static int s_state_chunk_data(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf);
static int s_state_chunk_data_crlf(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf);
static int s_state_trailer_line(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf);
static int s_state_done(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf);

/* Append to scratch, using reserve to grow if needed. Returns error if max length exceeded. */
static int s_scratch_append(struct aws_chunked_decoder *decoder, struct aws_byte_cursor data) {
    size_t new_len = decoder->scratch.len + data.len;
    if (new_len > AWS_CHUNKED_DECODER_MAX_LINE_LENGTH) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_GENERAL, "id=%p: parsing line exceed the max", (void *)decoder);
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }
    if (decoder->scratch.capacity == 0) {
        aws_byte_buf_init(&decoder->scratch, decoder->alloc, new_len);
    } else {
        aws_byte_buf_reserve(&decoder->scratch, new_len);
    }
    return aws_byte_buf_append_dynamic(&decoder->scratch, &data);
}

/**
 * Getline helper: scans input for a complete CRLF-terminated line, handling splits.
 * Returns:
 *  - AWS_OP_SUCCESS with *out_line set and *line_complete=true if a full line is available
 *  - AWS_OP_SUCCESS with *line_complete=false if more data needed (partial buffered in scratch)
 *  - AWS_OP_ERR on error (line too long)
 *
 * When line_complete=true, out_line points to the line content (without CRLF).
 * If scratch was used, out_line points into scratch (caller must reset scratch after processing).
 * If scratch was not used, out_line points into the original input buffer.
 */
static int s_getline(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_cursor *out_line,
    bool *line_complete) {
    *line_complete = false;

    /* Handle split CRLF: scratch ends with \r, input starts with \n */
    if (decoder->scratch.len > 0 && decoder->scratch.buffer[decoder->scratch.len - 1] == s_cr) {
        if (input->len > 0 && input->ptr[0] == s_lf) {
            aws_byte_cursor_advance(input, 1);
            decoder->scratch.len -= 1; /* remove trailing \r */
            *out_line = aws_byte_cursor_from_buf(&decoder->scratch);
            *line_complete = true;
            return AWS_OP_SUCCESS;
        }
    }

    /* Scan input for CRLF */
    struct aws_byte_cursor found;
    if (aws_byte_cursor_find_exact(input, &s_crlf, &found) == AWS_OP_SUCCESS) {
        size_t crlf_pos = (size_t)(found.ptr - input->ptr) + 2;
        struct aws_byte_cursor before_crlf = aws_byte_cursor_advance(input, crlf_pos);
        before_crlf.len -= 2;

        if (decoder->scratch.len > 0) {
            if (s_scratch_append(decoder, before_crlf)) {
                return AWS_OP_ERR;
            }
            *out_line = aws_byte_cursor_from_buf(&decoder->scratch);
        } else {
            *out_line = before_crlf;
        }
        *line_complete = true;
        return AWS_OP_SUCCESS;
    }

    /* No CRLF — buffer and wait */
    if (s_scratch_append(decoder, *input)) {
        return AWS_OP_ERR;
    }
    input->ptr += input->len;
    input->len = 0;
    return AWS_OP_SUCCESS;
}

/*
 * Parse a complete chunk-size line. Format: "<HEX-SIZE>;chunk-signature=<value>"
 * Example: "5;chunk-signature=UNSIGNED-PAYLOAD"
 * On size > 0: transition to CHUNK_DATA. On size == 0: terminal chunk, transition to TRAILER_LINE.
 */
static int s_parse_chunk_size_line(struct aws_chunked_decoder *decoder, struct aws_byte_cursor line) {
    /* Split on ';' to get hex size (first segment before ';') */
    struct aws_byte_cursor hex_part = {0};
    aws_byte_cursor_next_split(&line, ';', &hex_part);

    uint64_t size = 0;
    if (aws_byte_cursor_utf8_parse_u64_hex(hex_part, &size)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_GENERAL, "id=%p: invalid hex in chunk size line", (void *)decoder);
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }

    if (size == 0) {
        if (decoder->expected_content_length_set && decoder->total_decoded != decoder->expected_content_length) {
            AWS_LOGF_ERROR(
                AWS_LS_SDKUTILS_GENERAL,
                "id=%p: decoded length %" PRIu64 " does not match expected %" PRIu64,
                (void *)decoder,
                decoder->total_decoded,
                decoder->expected_content_length);
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }
        AWS_LOGF_TRACE(AWS_LS_SDKUTILS_GENERAL, "id=%p: terminal chunk, transitioning to trailers", (void *)decoder);
        decoder->state = s_state_trailer_line;
    } else {
        AWS_LOGF_TRACE(AWS_LS_SDKUTILS_GENERAL, "id=%p: chunk size=%" PRIu64, (void *)decoder, size);
        decoder->chunk_size = size;
        decoder->chunk_processed = 0;
        decoder->state = s_state_chunk_data;
    }
    return AWS_OP_SUCCESS;
}

/*
 * State: CHUNK_SIZE_LINE — accumulate bytes until CRLF, then parse the chunk size.
 * Example line: "5;chunk-signature=UNSIGNED-PAYLOAD\r\n"
 */
static int s_state_chunk_size_line(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    (void)output_buf;

    struct aws_byte_cursor line;
    bool line_complete;
    if (s_getline(decoder, input, &line, &line_complete)) {
        return AWS_OP_ERR;
    }
    if (!line_complete) {
        return AWS_OP_SUCCESS;
    }

    int rc = s_parse_chunk_size_line(decoder, line);
    /* Done with this line, reset scratch which may have been holding it */
    decoder->scratch.len = 0;
    return rc;
}

/*
 * State: CHUNK_DATA — writes decoded data bytes into the caller's output buffer.
 * Consumes up to (chunk_size - chunk_processed) bytes from input, then transitions to CHUNK_DATA_CRLF.
 */
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
    if (aws_byte_buf_append(output_buf, &data)) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_GENERAL, "id=%p: output buffer too small", (void *)decoder);
        return AWS_OP_ERR;
    }

    decoder->chunk_processed += to_copy;
    decoder->total_decoded += to_copy;
    if (decoder->chunk_processed == decoder->chunk_size) {
        decoder->chunk_processed = 0; /* reused as CRLF byte index in next state */
        decoder->state = s_state_chunk_data_crlf;
    }
    return AWS_OP_SUCCESS;
}

/*
 * State: CHUNK_DATA_CRLF — consume the "\r\n" that terminates chunk data.
 * After success, transitions back to CHUNK_SIZE_LINE for the next chunk.
 * Uses chunk_processed to track: 0 = expecting `\r`, 1 = expecting `\n`.
 */
static int s_state_chunk_data_crlf(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    (void)output_buf;

    while (input->len > 0 && decoder->chunk_processed < 2) {
        uint8_t expected = (decoder->chunk_processed == 0) ? s_cr : s_lf;
        if (input->ptr[0] != expected) {
            AWS_LOGF_ERROR(
                AWS_LS_SDKUTILS_GENERAL,
                "id=%p: expected CRLF after chunk data, but got unexpected byte",
                (void *)decoder);
            return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
        }
        aws_byte_cursor_advance(input, 1);
        decoder->chunk_processed++;
    }

    if (decoder->chunk_processed == 2) {
        decoder->state = s_state_chunk_size_line;
    }
    return AWS_OP_SUCCESS;
}

/*
 * Parse a complete trailer line. Format: "<name>:<value>" or empty line signals end.
 * Example: "trailer-key: abc123=="
 * Empty line ("\r\n" with no content) means all trailers are done → transition to DONE.
 */
static int s_parse_trailer_line(struct aws_chunked_decoder *decoder, struct aws_byte_cursor line) {
    if (line.len == 0) {
        AWS_LOGF_TRACE(
            AWS_LS_SDKUTILS_GENERAL,
            "id=%p: decode complete, total bytes=%" PRIu64,
            (void *)decoder,
            decoder->total_decoded);
        decoder->is_done = true;
        decoder->state = s_state_done;
        return AWS_OP_SUCCESS;
    }

    uint8_t *colon = memchr(line.ptr, ':', line.len);
    if (colon == NULL) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_GENERAL, "id=%p: malformed trailer line, no colon separator", (void *)decoder);
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

/*
 * State: TRAILER_LINE — accumulate bytes until CRLF, then parse as "name:value" trailer.
 * Invokes on_trailer callback for each trailer. Empty line signals completion.
 */
static int s_state_trailer_line(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {

    (void)output_buf;

    struct aws_byte_cursor line;
    bool line_complete;
    if (s_getline(decoder, input, &line, &line_complete)) {
        return AWS_OP_ERR;
    }
    if (!line_complete) {
        return AWS_OP_SUCCESS;
    }

    int rc = s_parse_trailer_line(decoder, line);
    /* Done with this line, reset scratch which may have been holding it */
    decoder->scratch.len = 0;
    return rc;
}

/*
 * State: DONE — decoding is complete. Any further input is an error.
 */
static int s_state_done(
    struct aws_chunked_decoder *decoder,
    struct aws_byte_cursor *input,
    struct aws_byte_buf *output_buf) {
    (void)output_buf;
    (void)decoder;
    if (input->len > 0) {
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_GENERAL, "id=%p: unexpected data after decode complete", (void *)decoder);
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }
    return AWS_OP_SUCCESS;
}

struct aws_chunked_decoder *aws_chunked_decoder_new(const struct aws_chunked_decoder_options *options) {

    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->allocator);

    struct aws_chunked_decoder *decoder = aws_mem_calloc(options->allocator, 1, sizeof(struct aws_chunked_decoder));

    decoder->alloc = options->allocator;
    decoder->state = s_state_chunk_size_line;
    decoder->on_trailer = options->on_trailer;
    decoder->user_data = options->user_data;
    if (options->expected_content_length != NULL) {
        decoder->expected_content_length = *options->expected_content_length;
        decoder->expected_content_length_set = true;
    }

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
        AWS_LOGF_ERROR(AWS_LS_SDKUTILS_GENERAL, "id=%p: unexpected data after decode complete", (void *)decoder);
        decoder->has_error = true;
        return aws_raise_error(AWS_ERROR_SDKUTILS_PARSE_FATAL);
    }

    return AWS_OP_SUCCESS;
}

bool aws_chunked_decoder_is_done(const struct aws_chunked_decoder *decoder) {
    AWS_PRECONDITION(decoder);
    return decoder->is_done;
}
