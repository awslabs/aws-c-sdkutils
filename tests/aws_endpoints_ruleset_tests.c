/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/file.h>
#include <aws/common/string.h>
#include <aws/sdkutils/endpoints/ruleset.h>
#include <aws/testing/aws_test_harness.h>
#include <time.h>

static int read_file_contents(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *alloc,
    const struct aws_string *filename) {
    AWS_ZERO_STRUCT(*out_buf);
    struct aws_string *mode = aws_string_new_from_c_str(alloc, "r");
    FILE *fp = aws_fopen_safe(filename, mode);
    aws_string_destroy(mode);
    ASSERT_NOT_NULL(fp);

    int64_t file_size = 0;
    ASSERT_INT_EQUALS(aws_file_get_length(fp, &file_size), AWS_OP_SUCCESS);

    ASSERT_INT_EQUALS(aws_byte_buf_init(out_buf, alloc, (size_t)file_size), AWS_OP_SUCCESS);
    size_t read = fread(out_buf->buffer, 1, (size_t)file_size, fp);
    fclose(fp);

    /* TODO: On win size read seems to be smaller than what get length returns,
    but its still a valid json*/
    /* ASSERT_INT_EQUALS(file_size, read); */

    out_buf->len = read;

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(parse_ruleset_from_string, s_test_parse_ruleset_from_string)
static int s_test_parse_ruleset_from_string(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_buf buf;
    aws_sdkutils_library_init(allocator);

    struct aws_string *filename = aws_string_new_from_c_str(allocator, "sample_ruleset.json");

    ASSERT_INT_EQUALS(read_file_contents(&buf, allocator, filename), AWS_OP_SUCCESS);
    struct aws_byte_cursor ruleset_json = aws_byte_cursor_from_buf(&buf);

    clock_t begin = clock();
    struct aws_endpoints_ruleset *ruleset = aws_endpoints_ruleset_new_from_string(allocator, &ruleset_json);
    clock_t end = clock();
    double time_taken = (((double)(end - begin)) / CLOCKS_PER_SEC);
    AWS_LOGF_INFO(AWS_LS_SDKUTILS_ENDPOINTS_PARSING, "Parsed in(s): %f", time_taken);

    ASSERT_NOT_NULL(ruleset);

    aws_string_destroy(filename);
    aws_endpoints_ruleset_release(ruleset);
    aws_byte_buf_clean_up(&buf);
    aws_sdkutils_library_clean_up();
    return AWS_OP_SUCCESS;
}