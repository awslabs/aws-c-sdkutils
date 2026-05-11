/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_buf.h>
#include <aws/sdkutils/endpoints_bdd_engine.h>
#include <aws/sdkutils/partitions.h>
#include <aws/sdkutils/private/endpoints_types_impl.h>
#include <aws/testing/aws_test_harness.h>

AWS_TEST_CASE(endpoints_bdd_loader_basic, s_test_bdd_loader_basic)
static int s_test_bdd_loader_basic(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_allocator *default_allocator = aws_default_allocator();
    allocator = default_allocator;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "bdd_test.bin"));

    struct aws_byte_buf partitions_buf;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&partitions_buf, allocator, "sample_partitions.json"));
    struct aws_byte_cursor partitions_json = aws_byte_cursor_from_buf(&partitions_buf);

    struct aws_partitions_config *partitions = aws_partitions_config_new_from_string(allocator, partitions_json);
    ASSERT_NOT_NULL(partitions);

    struct aws_endpoints_bdd_engine *engine =
        aws_endpoints_bdd_engine_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode), partitions);
    ASSERT_NOT_NULL(engine);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&engine->version, "1.1"));
    ASSERT_UINT_EQUALS(17, aws_hash_table_get_entry_count(&engine->parameters));
    ASSERT_UINT_EQUALS(76, aws_array_list_length(&engine->conditions));
    ASSERT_UINT_EQUALS(97, aws_array_list_length(&engine->results));

    aws_endpoints_bdd_engine_release(engine);
    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&partitions_buf);
    aws_byte_buf_clean_up(&bytecode);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(endpoints_bdd_compiler_loader_roundtrip, s_test_bdd_compiler_loader_roundtrip)
static int s_test_bdd_compiler_loader_roundtrip(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_sdkutils_library_init(allocator);

    struct aws_byte_buf bytecode;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&bytecode, allocator, "simple_bdd_test.bin"));

    struct aws_byte_buf partitions_buf;
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&partitions_buf, allocator, "sample_partitions.json"));
    struct aws_byte_cursor partitions_json = aws_byte_cursor_from_buf(&partitions_buf);

    struct aws_partitions_config *partitions = aws_partitions_config_new_from_string(allocator, partitions_json);
    ASSERT_NOT_NULL(partitions);

    struct aws_endpoints_bdd_engine *engine =
        aws_endpoints_bdd_engine_new_from_bytecode(allocator, aws_byte_cursor_from_buf(&bytecode), partitions);
    ASSERT_NOT_NULL(engine);

    ASSERT_TRUE(aws_byte_cursor_eq_c_str(&engine->version, "1.1"));
    ASSERT_UINT_EQUALS(2, aws_hash_table_get_entry_count(&engine->parameters));
    ASSERT_UINT_EQUALS(2, aws_array_list_length(&engine->conditions));
    ASSERT_UINT_EQUALS(3, aws_array_list_length(&engine->results));
    ASSERT_UINT_EQUALS(3, aws_array_list_length(&engine->nodes));

    aws_endpoints_bdd_engine_release(engine);
    aws_partitions_config_release(partitions);
    aws_byte_buf_clean_up(&partitions_buf);
    aws_byte_buf_clean_up(&bytecode);

    return AWS_OP_SUCCESS;
}
