/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/sdkutils/endpoints_bdd_engine.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/testing/aws_test_harness.h>

AWS_TEST_CASE(endpoints_bdd_basic, s_test_bdd_basic)
static int s_test_bdd_basic(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "bdd/endpoint-bdd-encoded.bin"));

    struct aws_byte_buf partitions_buf;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&partitions_buf, allocator, "sample_partitions.json"));
    struct aws_byte_cursor partitions_json = aws_byte_cursor_from_buf(&partitions_buf);

    struct aws_partitions_config *partitions = aws_partitions_config_new_from_string(allocator, partitions_json);
    ASSERT_NOT_NULL(partitions);

    struct aws_endpoints_request_context *context = aws_endpoints_request_context_new(allocator);
    ASSERT_SUCCESS(aws_endpoints_request_context_add_string(
        allocator, context, aws_byte_cursor_from_c_str("Region"), aws_byte_cursor_from_c_str("us-west-2")));
    ASSERT_SUCCESS(aws_endpoints_request_context_add_string(
        allocator, context, aws_byte_cursor_from_c_str("Bucket"), aws_byte_cursor_from_c_str("foobucket")));

    struct aws_endpoints_bdd_engine *engine =
        aws_endpoints_bdd_engine_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode), partitions);
    ASSERT_NOT_NULL(engine);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&engine->version, "1.1"));

    struct aws_endpoints_resolved_endpoint *resolved_endpoint = NULL;
    ASSERT_SUCCESS(aws_endpoints_bdd_engine_resolve(engine, context, &resolved_endpoint));

    ASSERT_INT_EQUALS(AWS_ENDPOINTS_RESOLVED_ENDPOINT, aws_endpoints_resolved_endpoint_get_type(resolved_endpoint));

    struct aws_byte_cursor url_cur;
    ASSERT_SUCCESS(aws_endpoints_resolved_endpoint_get_url(resolved_endpoint, &url_cur));

    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(url_cur, "https://foobucket.s3.us-west-2.amazonaws.com");

    aws_endpoints_resolved_endpoint_release(resolved_endpoint);
    aws_endpoints_bdd_engine_release(engine);

    aws_endpoints_request_context_release(context);
    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&partitions_buf);
    aws_byte_buf_clean_up(&bytecode);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(endpoints_bdd_s3_express, s_test_bdd_s3_express)
static int s_test_bdd_s3_express(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "bdd/endpoint-bdd-encoded.bin"));

    struct aws_byte_buf partitions_buf;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&partitions_buf, allocator, "sample_partitions.json"));
    struct aws_byte_cursor partitions_json = aws_byte_cursor_from_buf(&partitions_buf);

    struct aws_partitions_config *partitions = aws_partitions_config_new_from_string(allocator, partitions_json);
    ASSERT_NOT_NULL(partitions);

    struct aws_endpoints_request_context *context = aws_endpoints_request_context_new(allocator);
    ASSERT_SUCCESS(aws_endpoints_request_context_add_string(
        allocator, context, aws_byte_cursor_from_c_str("Region"), aws_byte_cursor_from_c_str("us-west-2")));
    ASSERT_SUCCESS(aws_endpoints_request_context_add_string(
        allocator,
        context,
        aws_byte_cursor_from_c_str("Bucket"),
        aws_byte_cursor_from_c_str("foobucket--usw2-az1--x-s3")));

    struct aws_endpoints_bdd_engine *engine =
        aws_endpoints_bdd_engine_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode), partitions);
    ASSERT_NOT_NULL(engine);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&engine->version, "1.1"));

    struct aws_endpoints_resolved_endpoint *resolved_endpoint = NULL;
    ASSERT_SUCCESS(aws_endpoints_bdd_engine_resolve(engine, context, &resolved_endpoint));

    ASSERT_INT_EQUALS(AWS_ENDPOINTS_RESOLVED_ENDPOINT, aws_endpoints_resolved_endpoint_get_type(resolved_endpoint));

    struct aws_byte_cursor url_cur;
    ASSERT_SUCCESS(aws_endpoints_resolved_endpoint_get_url(resolved_endpoint, &url_cur));

    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(
        url_cur, "https://foobucket--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com");

    aws_endpoints_resolved_endpoint_release(resolved_endpoint);
    aws_endpoints_bdd_engine_release(engine);

    aws_endpoints_request_context_release(context);
    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&partitions_buf);
    aws_byte_buf_clean_up(&bytecode);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(endpoints_bdd_s3_fips, s_test_bdd_s3_fips)
static int s_test_bdd_s3_fips(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "bdd/endpoint-bdd-encoded.bin"));

    struct aws_byte_buf partitions_buf;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&partitions_buf, allocator, "sample_partitions.json"));
    struct aws_byte_cursor partitions_json = aws_byte_cursor_from_buf(&partitions_buf);

    struct aws_partitions_config *partitions = aws_partitions_config_new_from_string(allocator, partitions_json);
    ASSERT_NOT_NULL(partitions);

    struct aws_endpoints_request_context *context = aws_endpoints_request_context_new(allocator);
    ASSERT_SUCCESS(aws_endpoints_request_context_add_string(
        allocator, context, aws_byte_cursor_from_c_str("Region"), aws_byte_cursor_from_c_str("us-west-2")));
    ASSERT_SUCCESS(aws_endpoints_request_context_add_string(
        allocator, context, aws_byte_cursor_from_c_str("Bucket"), aws_byte_cursor_from_c_str("foobucket")));
    ASSERT_SUCCESS(
        aws_endpoints_request_context_add_boolean(allocator, context, aws_byte_cursor_from_c_str("UseFIPS"), true));

    struct aws_endpoints_bdd_engine *engine =
        aws_endpoints_bdd_engine_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode), partitions);
    ASSERT_NOT_NULL(engine);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&engine->version, "1.1"));

    struct aws_endpoints_resolved_endpoint *resolved_endpoint = NULL;
    ASSERT_SUCCESS(aws_endpoints_bdd_engine_resolve(engine, context, &resolved_endpoint));

    ASSERT_INT_EQUALS(AWS_ENDPOINTS_RESOLVED_ENDPOINT, aws_endpoints_resolved_endpoint_get_type(resolved_endpoint));

    struct aws_byte_cursor url_cur;
    ASSERT_SUCCESS(aws_endpoints_resolved_endpoint_get_url(resolved_endpoint, &url_cur));

    ASSERT_CURSOR_VALUE_CSTRING_EQUALS(url_cur, "https://foobucket.s3-fips.us-west-2.amazonaws.com");

    aws_endpoints_resolved_endpoint_release(resolved_endpoint);
    aws_endpoints_bdd_engine_release(engine);

    aws_endpoints_request_context_release(context);
    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&partitions_buf);
    aws_byte_buf_clean_up(&bytecode);

    return AWS_OP_SUCCESS;
}
